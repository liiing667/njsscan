"""Test njsscan-ignore comment suppression."""
import json

from pathlib import Path

from .setup_test import scanner

from njsscan.formatters import (
    json_out,
    sarif,
    sonarqube,
)
from njsscan.njsscan import get_ignored_rule_ids


ASSETS = Path(__file__).parents[1] / 'assets' / 'ignore_comments'


def test_ignore_comment_rule_id_exact_match():
    res = scanner([ASSETS / 'xss_ignore.js'], False)
    xss = res['nodejs'].get('express_xss')
    assert xss is not None
    # `njsscan-ignore: express_xss_fast` must not suppress `express_xss`,
    # only the exact `njsscan-ignore: express_xss` hit is removed.
    start_lines = sorted(
        f['match_lines'][0] for f in xss['files'])
    assert start_lines == [5, 13]


def test_ignore_comment_multi_line_template():
    res = scanner([ASSETS / 'multi_line.hbs'], False)
    squirrelly = res['templates'].get('squirrelly_template')
    assert squirrelly is not None
    # The ignore comment on the last line of a multi-line match
    # suppresses it, the uncommented match remains.
    assert len(squirrelly['files']) == 1
    assert squirrelly['files'][0]['match_lines'] == (5, 5)


def test_get_ignored_rule_ids():
    assert get_ignored_rule_ids(None) == set()
    assert get_ignored_rule_ids('var a = 1;') == set()
    ids = get_ignored_rule_ids(
        'x(); // njsscan-ignore: rule_one, rule_two')
    assert ids == {'rule_one', 'rule_two'}
    ids = get_ignored_rule_ids(
        'x(); //njsscan-ignore: express_xss_fast')
    assert ids == {'express_xss_fast'}
    assert 'express_xss' not in ids


def test_remaining_results_consistent_across_formats():
    res = scanner([ASSETS / 'xss_ignore.js'], False)
    expected_lines = [5, 13]

    jout = json.loads(json_out.json_output(None, res, '0.0.0'))
    json_files = jout['nodejs']['express_xss']['files']
    assert sorted(
        f['match_lines'][0] for f in json_files) == expected_lines
    json_paths = {f['file_path'] for f in json_files}
    assert len(json_paths) == 1
    file_path = json_paths.pop()
    assert file_path.endswith('xss_ignore.js')

    sout = json.loads(sarif.sarif_output(None, res, '0.0.0'))
    sarif_results = [
        r for r in sout['runs'][0]['results']
        if r['ruleId'] == 'express_xss']
    assert len(sarif_results) == 2
    for result in sarif_results:
        loc = result['locations'][0]['physicalLocation']
        assert loc['artifactLocation']['uri'].endswith('xss_ignore.js')
    assert sorted(
        r['locations'][0]['physicalLocation']['region']['startLine']
        for r in sarif_results) == expected_lines

    qout = json.loads(sonarqube.sonarqube_output(None, res, '0.0.0'))
    sonar_issues = [
        i for i in qout['issues'] if i['ruleId'] == 'express_xss']
    assert len(sonar_issues) == 1
    issue = sonar_issues[0]
    primary = issue['primaryLocation']
    assert primary['filePath'] == file_path
    sonar_lines = [primary['textRange']['startLine']]
    sonar_lines.extend(
        loc['textRange']['startLine']
        for loc in issue.get('secondaryLocations', []))
    for loc in issue.get('secondaryLocations', []):
        assert loc['filePath'] == file_path
    assert sorted(sonar_lines) == expected_lines
