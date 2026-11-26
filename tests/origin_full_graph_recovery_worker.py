"""Owned subprocess for the B4.2C full local graph recovery lab (killed/restarted by the parent).

Modes: start | resume | finalize (resume with finalize_only=True). The decision engine and the
KnowledgeStore writers are replaced by failing stubs: any LLM or knowledge write aborts the run.
"""
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ['PYTHON_DOTENV_DISABLED'] = '1'
os.environ['LANGCHAIN_TRACING_V2'] = 'false'
os.environ['LANGSMITH_TRACING'] = 'false'

from src.coordinator import graph
from src.coordinator.graph import run_pipeline
from src.coordinator.knowledge_store import KnowledgeStore
from src.coordinator.origin_local import LocalOriginTest
from src.coordinator.origin_recovery import RecoveryJournal, utc
from src.coordinator.artifacts import RunArtifacts


def forbidden(*args, **kwargs):
    raise AssertionError('B4.2C lab: LLM provider or KnowledgeStore write attempted')


def identity_of(journal, payload, kind):
    """Resolve the stage identity (probe | soft404) behind a journal event."""
    probe = payload.get(kind)
    if not (probe and 'role' in probe):
        seq = payload.get('sequence')
        reservation = next((e['payload'] for e in journal.events if e['event'] == 'reserved'
                            and e['payload'].get('sequence') == seq), None)
        probe = (reservation or {}).get(kind)
    if not probe:
        return None
    units = []
    for e in journal.events:
        unit = (e['payload'].get(kind) or {}).get('unit_id') if e['event'] == 'reserved' else None
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
            spec = dict(hook['probe'])
            probe = identity_of(self, payload, spec.pop('kind'))
            if probe is None or any(probe.get(k) != v for k, v in spec.items()):
                return
        RunArtifacts._write_json(directory / (label + '_barrier.json'),
                                 {'pid': os.getpid(), 'utc': utc(), 'event': event, 'payload': payload})
        expires = time.monotonic() + 30
        while not (directory / (label + '_release')).exists():
            if time.monotonic() > expires:
                raise TimeoutError('bounded_test_barrier')
            time.sleep(.02)
    RecoveryJournal.barrier = barrier
    graph._get_decision_engine = forbidden
    KnowledgeStore.save_lessons = KnowledgeStore.save_session = KnowledgeStore.save_decision_pattern = forbidden
    a = settings['target'].rstrip('/')
    profiles = {a: {'profile_id': 'frontend', 'headers': {'Authorization': settings['auth'], 'Cookie': settings['cookie']}}}
    RunArtifacts._write_json(directory / (label + '_process.json'), {'pid': os.getpid(), 'utc': utc(), 'mode': mode})
    try:
        local = LocalOriginTest(settings['target'], scope=settings['config']['multi_origin'],
                                documents=settings['documents'], origin_max_requests=settings['quotas'],
                                credential_profiles=profiles, recovery_directory=directory / 'recovery',
                                resume=mode in ('resume', 'finalize'), finalize_only=mode == 'finalize',
                                parameter_verification=settings.get('parameter_verification', True),
                                parameter_max_requests=settings.get('parameter_max_requests', 200),
                                soft404_verification=settings.get('soft404_verification', True),
                                soft404_max_requests=settings.get('soft404_max_requests', 200))
        result = run_pipeline(settings['target'], settings['config'], local_origin_test=local)
        RunArtifacts._write_json(directory / (label + '_result.json'), result)
    except Exception as exc:
        RunArtifacts._write_json(directory / (label + '_denied.json'), {'error_type': type(exc).__name__, 'reason': str(exc)})


if __name__ == '__main__':
    main()
