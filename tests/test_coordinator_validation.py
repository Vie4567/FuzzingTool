from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from src.coordinator.validation import validate_pipeline_input, validate_wordlist, InputValidationError


class CoordinatorValidationTests(unittest.TestCase):
    def test_url_rejects_malformed_or_credential_destinations(self):
        for url in (None, 17, '', 'https://', 'ftp://example.com', 'https://x:0', 'https://x:65536',
                    'https://x:', 'https://user:pass@x', 'https://x/#fragment', 'https://x/a\n',
                    'https://x/a%0d', 'https://x/%zz', 'https://bad_host/', 'https://[bad', '//x',
                    'https://x\\@evil.test', 'https://x/FUZZ', 'http://999.999.999.999',
                    'http://127.1', 'http://0177.0.0.1', 'http://2130706433', 'http://0x7f000001'):
            with self.subTest(url=url), self.assertRaises(InputValidationError):
                validate_pipeline_input(url)

    def test_valid_local_ipv6_idna_and_normalization(self):
        for url in ('http://localhost:8000', 'http://127.0.0.1:80', 'https://[::1]:8443',
                    'https://tên.vn/path?x=1'):
            target, c = validate_pipeline_input(url)
            self.assertTrue(target.startswith(('http://', 'https://')))
            self.assertEqual(c['llm_timeout_seconds'], 30)
        self.assertEqual(validate_pipeline_input('https://[0:0:0:0:0:0:0:1]:443/')[0], 'https://[::1]/')
        self.assertEqual(validate_pipeline_input('https://example.test/caf\u00e9?q=\u00e9')[0],
                         'https://example.test/caf%C3%A9?q=%C3%A9')

    def test_reject_config_types_nonfinite_unknown_and_nested_errors(self):
        bad = [[], '', {'wrong': 1}, {'max_retries': True}, {'max_retries': -1},
               {'pipeline_timeout_seconds': float('inf')}, {'llm_timeout_seconds': float('nan')},
               {'fuzzing_options': {'threads': '2'}}, {'fuzzing_options': {'engine': 'invented'}},
               {'fuzzing_options': {'wrong': 2}}, {'soft404_options': {'enabled': 'yes'}},
               {'parameter_options': []}, {'recon_options': {'headers': {'Authorization': 'x\r\ny'}}},
               {'recon_options': {'verify_ssl': False}}, {'recon_options': {'auth_origins': ['https://elsewhere.test']}},
               {'wordlist_mode': 'provided'}, {'wordlist': []}, {'base_url': 'https://user:pass@host'}]
        bad += [{'wordlist_mode': []}, {'wordlist_mode': {}}, {'max_retries': 10**1000},
                {'fuzzing_options': {'engine': []}}, {'fuzzing_options': {'headers': {'X-Value': '\u2603'}}},
                {'token': 'secret\x1f'}, {'cookie': '\u2603'}, {'recon_options': {'account': None}},
                {'soft404_options': {'distinct_threshold': .99, 'similarity_threshold': .9}},
                {'parameter_options': {'max_response_bytes': 8*1024*1024+1}},
                {'fuzzing_options': {'extensions': ['php\r\nsecret']}},
                {'fuzzing_options': {'filter_codes': ['599-100']}},
                {'fuzzing_options': {'filter_codes': ['secret']}},
                {'fuzzing_options': {'filter_codes': True}}]
        for config in bad:
            with self.subTest(config=config), self.assertRaises(InputValidationError):
                validate_pipeline_input('https://example.test', config)

    def test_wordlist_file_dedup_and_no_caller_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'words.txt'
            path.write_text('/a\n/a\n\n/b\n', encoding='utf-8')
            config = {'wordlist_file': str(path), 'wordlist_mode': 'merge'}
            original = deepcopy(config)
            target, normalized = validate_pipeline_input('https://example.test', config)
            self.assertEqual(normalized['wordlist'], ['/a', '/b'])
            self.assertEqual(validate_pipeline_input(target, normalized)[1], normalized)
            self.assertEqual(original, config)

    def test_wordlist_rejects_outside_scope_and_does_not_echo_secrets(self):
        for words in ('abc', [None], ['//evil.test/a'], ['https://evil.test/a'], ['a\nsecret'], ['/a%00'], ['a#fragment']):
            with self.subTest(words=words), self.assertRaises(InputValidationError) as caught:
                validate_wordlist('https://example.test', words)
            self.assertNotIn('secret', str(caught.exception))
        self.assertEqual(validate_wordlist('https://example.test', ['/a', 'https://example.test/a']), ['/a'])
        self.assertEqual(validate_wordlist('https://example.test:443', ['https://example.test/a']), ['/a'])

    def test_conflicting_aliases_are_rejected_and_equal_aliases_normalized(self):
        for canonical, alias, a, b in (('rate_limit', 'rate', 1, 2), ('threads', 'workers', 1, 2),
                ('timeout_seconds', 'timeout', 1, 2), ('http_method', 'method', 'GET', 'POST'),
                ('post_data', 'body', 'one', 'two'), ('max_scan_seconds', 'max_duration_seconds', 1, 2)):
            with self.subTest(alias=alias), self.assertRaises(InputValidationError):
                validate_pipeline_input('https://example.test', {'fuzzing_options': {canonical: a, alias: b}})
        config = {'fuzzing_options': {'engine': 'python_http', 'rate': 1, 'rate_limit': 1,
                                     'workers': 1, 'timeout': 2, 'method': 'GET'}}
        original = deepcopy(config)
        target, normalized = validate_pipeline_input('https://example.test', config)
        self.assertEqual(config, original)
        self.assertEqual(normalized['fuzzing_options'], {'engine': 'python_http', 'rate_limit': 1,
                                                       'threads': 1, 'timeout_seconds': 2, 'http_method': 'GET'})
        self.assertEqual(validate_pipeline_input(target, normalized)[1], normalized)

    def test_native_engine_rejects_options_it_cannot_apply(self):
        for options in ({'threads': 2}, {'auto_calibrate': True}, {'recursion': True},
                        {'filter_codes': [404]}, {'extensions': ['php']}, {'match_codes': '200'},
                        {'proxy_count': 2}, {'allowed_origins': ['https://example.test']},
                        {'lab_source_ips': ['127.0.0.2']}, {'verify_ssl': False},
                        {'headers': {'X-Forwarded-For': '127.0.0.1'}}, {'proxy': 'socks5://localhost:8080'}):
            with self.subTest(options=options), self.assertRaises(InputValidationError):
                validate_pipeline_input('https://example.test', {'fuzzing_options': {'engine': 'python_http', **options}})
        with patch('src.tools.ffuf_helper.FfufToolHelper.resolve_binary', return_value=None):
            with self.assertRaises(InputValidationError):
                validate_pipeline_input('https://example.test', {'fuzzing_options': {'engine': 'ffuf_cli'}})
            with self.assertRaises(InputValidationError):
                validate_pipeline_input('https://example.test', {'fuzzing_options': {'engine': 'auto', 'recursion': True}})

    def test_proxy_pool_scope_and_limits_validated_without_network(self):
        base = {'engine': 'proxy_http', 'proxy_source': 'proxyscrape',
                'allowed_origins': ['https://example.test'], 'proxy_count': 2}
        bad = ({'proxy_healthcheck_url': 'https://other.test/check'}, {'proxy_refresh_seconds': 10},
               {'max_duration_seconds': 601}, {'rate': 11}, {'timeout': 31}, {'stop_on_429': False},
               {'lab_source_ips': ['127.0.0.2']}, {'proxy_profiles': [{'id': 'one', 'url': 'http://localhost:8000'}]})
        with patch('src.tools.proxyscrape.fetch_candidates') as fetch, patch('socket.create_connection') as connect:
            validate_pipeline_input('https://example.test', {'fuzzing_options': base})
            for options in bad:
                with self.subTest(options=options), self.assertRaises(InputValidationError):
                    validate_pipeline_input('https://example.test', {'fuzzing_options': {**base, **options}})
            fetch.assert_not_called()
            connect.assert_not_called()

    def test_loopback_scope_source_family_and_stricter_limits(self):
        validate_pipeline_input('http://127.0.0.1:8000', {'fuzzing_options': {'engine': 'loopback_lab'}})
        bad = ({'lab_source_ips': ['192.0.2.1']}, {'lab_source_ips': ['::1']}, {'threads': 2},
               {'rate_limit': 11}, {'timeout_seconds': 11}, {'max_scan_seconds': 61},
               {'max_requests': 101}, {'stop_on_block': False}, {'proxy': 'http://localhost:8080'})
        for options in bad:
            with self.subTest(options=options), self.assertRaises(InputValidationError):
                validate_pipeline_input('http://127.0.0.1:8000', {'fuzzing_options': {'engine': 'loopback_lab', **options}})
        with self.assertRaises(InputValidationError):
            validate_pipeline_input('https://example.test', {'fuzzing_options': {'engine': 'loopback_lab'}})

    def test_invalid_files_and_credentials_produce_only_field_constraints(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private_secret_wordlist.txt'
            for contents in (b'\xff', b'\n\n', b'x' * (8*1024*1024+1)):
                path.write_bytes(contents)
                with self.assertRaises(InputValidationError) as caught:
                    validate_pipeline_input('https://example.test', {'wordlist_file': str(path)})
                self.assertNotIn('private_secret', str(caught.exception))
        for options in ({'proxy': 'http://user:supersecret@999.999.999.999:8080'},
                        {'proxy': 'http://user:supersecret%0a@proxy.test:8080'},
                        {'proxy': 'http://user:supersecret@proxy.test:'}):
            with self.subTest(options=options), self.assertRaises(InputValidationError) as caught:
                validate_pipeline_input('https://example.test', {'fuzzing_options': {'engine': 'python_http', **options}})
            self.assertNotIn('supersecret', str(caught.exception))

    def test_scope_credentials_and_relative_ca_survive_worker_directory_change(self):
        ca = Path('tests/fixtures/proxy_lab_cert.pem')
        target, config = validate_pipeline_input('https://example.test', {
            'tls_ca_file': str(ca), 'recon_options': {'tls_ca_file': str(ca)},
            'parameter_options': {'tls_ca_file': str(ca)}, 'soft404_options': {'tls_ca_file': str(ca)}})
        self.assertEqual(config['tls_ca_file'], str(ca.resolve()))
        for section in ('recon_options', 'parameter_options', 'soft404_options'):
            self.assertEqual(config[section]['tls_ca_file'], str(ca.resolve()))
        self.assertEqual(validate_pipeline_input(target, config)[1], config)
        bad = ({'auth_origins': [], 'account': {'username': 'fixture', 'password': 'fixture',
                                              'login_url': 'https://example.test/login'}},
               {'headers': {'Authorization': 'one', 'authorization': 'two'}},
               {'tls_ca_file': ''}, {'base_url': 'https://api.example.test/v1?secret=hidden'})
        for config in bad:
            with self.subTest(config=config), self.assertRaises(InputValidationError):
                validate_pipeline_input('https://example.test', config)
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'file.txt'
            file.write_text('not a directory', encoding='utf-8')
            for key in ('artifact_root', 'knowledge_store_dir', 'output_dir'):
                with self.subTest(key=key), self.assertRaises(InputValidationError):
                    validate_pipeline_input('https://example.test', {key: str(file / 'child')})
