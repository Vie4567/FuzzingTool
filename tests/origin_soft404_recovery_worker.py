"""Owned subprocess for the B4.2B loopback Soft404-recovery lab (killed/restarted by the parent)."""
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ['PYTHON_DOTENV_DISABLED'] = '1'
os.environ['LANGCHAIN_TRACING_V2'] = 'false'
os.environ['LANGSMITH_TRACING'] = 'false'

from src.coordinator.graph import run_pipeline
from src.coordinator.origin_local import LocalOriginTest
from src.coordinator.origin_recovery import RecoveryJournal, utc
from src.coordinator.artifacts import RunArtifacts


def probe_of(journal, payload):
    """Resolve the Soft404 identity behind a journal event (by sequence for request events)."""
    probe = payload.get('soft404')
    if not (probe and 'role' in probe):
        seq = payload.get('sequence')
        reservation = next((e['payload'] for e in journal.events if e['event'] == 'reserved'
                            and e['payload'].get('sequence') == seq), None)
        probe = (reservation or {}).get('soft404')
    if not probe:
        return None
    units = []
    for e in journal.events:
        unit = (e['payload'].get('soft404') or {}).get('unit_id') if e['event'] == 'reserved' else None
        if unit and unit not in units:
            units.append(unit)
    return {**probe, 'unit_index': units.index(probe['unit_id']) if probe['unit_id'] in units else len(units)}


def main():
    config_path, mode, label = sys.argv[1:]
    settings = json.loads(Path(config_path).read_text(encoding='utf-8'))
    directory = Path(config_path).parent
    hook = settings.get('barrier', {}) if mode == 'start' else settings.get('resume_barrier', {})

    def barrier(self, event, payload):
        if event != hook.get('event'):
            return
        if any(payload.get(k) != v for k, v in hook.get('match', {}).items()):
            return
        if 'probe' in hook:
            probe = probe_of(self, payload)
            if probe is None or any(probe.get(k) != v for k, v in hook['probe'].items()):
                return
        RunArtifacts._write_json(directory / (label + '_barrier.json'),
                                 {'pid': os.getpid(), 'utc': utc(), 'event': event, 'payload': payload})
        expires = time.monotonic() + 30
        while not (directory / (label + '_release')).exists():
            if time.monotonic() > expires:
                raise TimeoutError('bounded_test_barrier')
            time.sleep(.02)
    RecoveryJournal.barrier = barrier
    a = settings['target'].rstrip('/')
    profiles = {a: {'profile_id': 'frontend', 'headers': {'Authorization': settings['auth'], 'Cookie': settings['cookie']}}}
    RunArtifacts._write_json(directory / (label + '_process.json'), {'pid': os.getpid(), 'utc': utc(), 'mode': mode})
    try:
        local = LocalOriginTest(settings['target'], scope=settings['config']['multi_origin'],
                                documents=settings['documents'], origin_max_requests=settings['quotas'],
                                credential_profiles=profiles, recovery_directory=directory / 'recovery',
                                resume=mode == 'resume',
                                parameter_verification=settings.get('parameter_verification', False),
                                soft404_verification=settings.get('soft404_verification', True),
                                soft404_max_requests=settings.get('soft404_max_requests', 200))
        result = run_pipeline(settings['target'], settings['config'], local_origin_test=local)
        RunArtifacts._write_json(directory / (label + '_result.json'), result)
    except Exception as exc:
        RunArtifacts._write_json(directory / (label + '_denied.json'), {'error_type': type(exc).__name__, 'reason': str(exc)})


if __name__ == '__main__':
    main()
