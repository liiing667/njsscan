# -*- coding: utf_8 -*-
"""Tests for the report redaction boundary."""
import json

from njsscan.formatters import (
    cli,
    defectdojo,
    gitlab_sast,
    json_out,
    sarif,
    sonarqube,
)
from njsscan.njsscan import NJSScan
from njsscan.redaction import (
    MASK,
    mask_match_string,
    redact_metadata,
    redact_scan_results,
)

# Fake credentials from the hardcoded_secrets.js fixture. They must never
# reach a machine-readable report artifact.
FAKE_API_KEY = '6e906986c3b199c51fff3154cfb76979'
FAKE_PASSWORD = '1212'
SECRET_FIXTURE = (
    'tests/assets/node_source/true_positives/semantic_grep/'
    'generic/hardcoded_secrets.js')

MACHINE_FORMATTERS = (
    ('json', json_out.json_output),
    ('sarif', sarif.sarif_output),
    ('gitlab', gitlab_sast.gitlab_sast_output),
    ('defectdojo', defectdojo.defectdojo_output),
    ('sonar', sonarqube.sonarqube_output),
)


def test_mask_match_string_keeps_code_structure():
    masked = mask_match_string("password = '1212';")
    assert masked == f'password = {MASK};'


def test_mask_match_string_handles_all_quote_styles():
    assert mask_match_string('a = "x";') == f'a = {MASK};'
    assert mask_match_string("a = 'x';") == f'a = {MASK};'
    assert mask_match_string('a = `x`;') == f'a = {MASK};'


def test_mask_match_string_preserves_multiline_lists():
    masked = mask_match_string(
        ['const token = "abc";', 'use(token);'])
    assert masked == [f'const token = {MASK};', 'use(token);']


def test_secret_rule_multiline_snippet_without_literal_fully_masked():
    masked = mask_match_string(
        ['password assigned', 'from somewhere'],
        secret_rule=True)
    assert masked == [MASK, MASK]


def test_secret_rule_without_literal_is_fully_masked():
    snippet = 'password assigned from somewhere without quotes'
    assert mask_match_string(snippet, secret_rule=True) == MASK
    assert mask_match_string(snippet, secret_rule=False) == snippet


def test_redact_metadata_masks_only_sensitive_keys():
    metadata = {
        'description': 'A hardcoded secret is identified.',
        'severity': 'ERROR',
        'cwe': 'CWE-798',
        'owasp-web': 'A3',
        'api_key': FAKE_API_KEY,
        'nested': {'client_secret': FAKE_PASSWORD, 'keep': 'summary'},
    }
    redacted = redact_metadata(metadata)
    assert redacted['api_key'] == MASK
    assert redacted['nested']['client_secret'] == MASK
    assert redacted['nested']['keep'] == 'summary'
    assert redacted['description'] == metadata['description']
    assert redacted['severity'] == 'ERROR'
    assert redacted['cwe'] == 'CWE-798'


def test_redact_scan_results_does_not_mutate_input():
    scan_results = {
        'nodejs': {
            'node_secret': {
                'metadata': {'description': 'd', 'severity': 'ERROR'},
                'files': [{
                    'file_path': 'app.js',
                    'match_lines': [1, 1],
                    'match_position': [1, 20],
                    'match_string': "secret = 's3cr3t';",
                }],
            },
        },
        'templates': {},
        'errors': [],
    }
    redacted = redact_scan_results(scan_results)
    assert scan_results['nodejs']['node_secret']['files'][0][
        'match_string'] == "secret = 's3cr3t';"
    assert MASK in redacted['nodejs']['node_secret']['files'][0][
        'match_string']


def _secret_scan():
    return NJSScan([SECRET_FIXTURE], True, False).scan()


def test_hardcoded_secret_fixture_contains_raw_credentials():
    raw = json.dumps(_secret_scan())
    assert FAKE_API_KEY in raw
    assert FAKE_PASSWORD in raw


def test_machine_reports_redact_fake_credentials():
    scan_results = _secret_scan()
    for name, formatter in MACHINE_FORMATTERS:
        report = formatter(None, scan_results, '0.0.0')
        assert FAKE_API_KEY not in report, name
        assert FAKE_PASSWORD not in report, name


def test_json_report_preserves_rule_path_position_and_summary():
    report = json.loads(json_out.json_output(None, _secret_scan(), '0.0.0'))
    issue = report['nodejs']['node_api_key']
    match = issue['files'][0]
    assert match['file_path'] == SECRET_FIXTURE
    assert match['match_lines'] == [32, 32]
    assert match['match_position'] == [1, 95]
    assert MASK in match['match_string']
    assert issue['metadata']['severity'] == 'ERROR'
    assert issue['metadata']['cwe'].startswith('CWE-798')
    assert 'hardcoded API Key' in issue['metadata']['description']


def test_sarif_snippet_is_masked_but_region_kept():
    report = json.loads(sarif.sarif_output(None, _secret_scan(), '0.0.0'))
    result = next(
        item for item in report['runs'][0]['results']
        if item['ruleId'] == 'node_password')
    region = result['locations'][0]['physicalLocation']['region']
    assert region['snippet']['text'] == f'password = {MASK};'
    assert region['startLine'] == 2
    assert region['endLine'] == 2
    assert region['startColumn'] == 1
    assert result['message']['text'].startswith('A hardcoded password')


def test_defectdojo_description_uses_masked_match():
    report = json.loads(
        defectdojo.defectdojo_output(None, _secret_scan(), '0.0.0'))
    for finding in report['findings']:
        assert FAKE_API_KEY not in finding['description']
        assert FAKE_PASSWORD not in finding['description']


def test_console_diagnostics_keep_raw_snippet():
    buffer = cli.cli_output(None, _secret_scan(), '0.0.0', 'fancy_grid')
    console = '\n'.join(buffer)
    assert FAKE_API_KEY in console
    assert FAKE_PASSWORD in console
