# -*- coding: utf_8 -*-
"""JSON output format."""
import json

from njsscan.redaction import redact_scan_results


def json_output(outfile, scan_results, version):
    """JSON Output."""
    safe_results = redact_scan_results(scan_results)
    safe_results['njsscan_version'] = version
    jout = json.dumps(
        safe_results,
        sort_keys=True,
        indent=2,
        separators=(',', ': '))
    if outfile:
        with open(outfile, 'w') as of:
            of.write(jout)
    else:
        print(jout)
    return jout
