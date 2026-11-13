# -*- coding: utf_8 -*-
"""Redaction boundary for machine-readable scan reports.

Hardcoded credential rules return the offending source line in
``match_string``, so writing the raw findings to CI artifacts would leak
the secret a second time. JSON, SARIF, GitLab SAST, DefectDojo and
SonarQube reports therefore pass through :func:`redact_scan_results`,
which masks quoted secret values inside snippets and sensitive values in
rule metadata while preserving rule ids, paths, line/column positions and
summaries. The console diagnostics keep the raw text for local triage.
"""
import copy
import re

MASK = '***REDACTED***'

# Rules that flag hardcoded credentials. When such a rule fires but no
# quoted literal can be located in the snippet, the whole snippet is
# masked rather than risking an unquoted secret reaching the report.
SECRET_RULE_RE = re.compile(
    r'(?i)(secret|password|passwd|api[_-]?key|token|credential)')

# Metadata keys whose values may carry credentials. Summary fields such as
# description, severity, cwe and owasp-web are never matched.
SENSITIVE_META_RE = SECRET_RULE_RE

# Double, single and backtick quoted literals. The character classes stop
# at the matching quote while honoring escaped quotes.
_STRING_LITERAL_RE = re.compile(
    r'"(?:\\.|[^"\\])*"'
    r"|'(?:\\.|[^'\\])*'"
    r'|`(?:\\.|[^`\\])*`')


def mask_match_string(match_string, secret_rule=False):
    """Mask every quoted literal inside a finding snippet.

    A snippet may be a single string, a list of source lines or an
    unexpected non-string value. Snippets from credential rules without a
    recognizable literal are masked wholesale as a safety net.
    """
    if isinstance(match_string, list):
        # Continuation lines of a multi-line match need not contain a
        # literal, so the no-literal safety net applies per whole snippet
        # rather than being inherited by every line.
        masked_lines = [mask_match_string(item) for item in match_string]
        has_literal = any(
            original != masked
            for original, masked in zip(match_string, masked_lines))
        if secret_rule and not has_literal and any(
                line.strip() for line in match_string):
            return [MASK for _ in masked_lines]
        return masked_lines
    if not isinstance(match_string, str):
        return MASK
    masked = _STRING_LITERAL_RE.sub(MASK, match_string)
    if secret_rule and masked == match_string and match_string.strip():
        return MASK
    return masked


def mask_metadata_value(value, sensitive=False):
    """Mask a sensitive metadata value, recursing into containers.

    When ``sensitive`` is set the whole value is a credential and every
    string inside it is masked; nested mappings still apply their own key
    names so that non-sensitive siblings keep their summaries.
    """
    if isinstance(value, str):
        return MASK if sensitive else value
    if isinstance(value, dict):
        return {
            key: mask_metadata_value(
                item,
                sensitive
                or (isinstance(key, str)
                    and bool(SENSITIVE_META_RE.search(key))))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        masked = [
            mask_metadata_value(item, sensitive)
            for item in value
        ]
        if isinstance(value, tuple):
            return tuple(masked)
        return masked
    return value


def redact_metadata(metadata):
    """Return a metadata copy with sensitive key values masked."""
    if not isinstance(metadata, dict):
        return copy.deepcopy(metadata)
    redacted = {}
    for key, value in metadata.items():
        if isinstance(key, str) and SENSITIVE_META_RE.search(key):
            redacted[key] = mask_metadata_value(value, sensitive=True)
        elif isinstance(value, (dict, list, tuple)):
            redacted[key] = mask_metadata_value(value)
        else:
            redacted[key] = value
    return redacted


def redact_files(files, secret_rule):
    """Mask snippet text for every file match of one rule."""
    redacted_files = []
    for file_item in files or []:
        redacted_item = dict(file_item)
        if 'match_string' in redacted_item:
            redacted_item['match_string'] = mask_match_string(
                redacted_item['match_string'],
                secret_rule)
        redacted_files.append(redacted_item)
    return redacted_files


def redact_section(section):
    """Mask snippets and sensitive metadata in one result section."""
    redacted_section = {}
    for rule_id, issue in section.items():
        redacted_issue = dict(issue)
        redacted_issue['metadata'] = redact_metadata(issue.get('metadata'))
        if issue.get('files'):
            redacted_issue['files'] = redact_files(
                issue['files'],
                bool(SECRET_RULE_RE.search(rule_id)))
        redacted_section[rule_id] = redacted_issue
    return redacted_section


def redact_scan_results(scan_results):
    """Return a deep, redacted copy of the full scan result mapping.

    The original result used by the console output is never mutated.
    """
    redacted = copy.deepcopy(scan_results)
    for section in ('nodejs', 'templates'):
        if redacted.get(section):
            redacted[section] = redact_section(redacted[section])
    return redacted
