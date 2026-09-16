"""Reviewable generated plugin helper.
ULPF runtime activation uses parser.yaml.
"""

import re

def parse(raw):
    result = {}
    pattern = re.compile(r'([A-Za-z_][\w.-]*)=(?:"([^"]*)"|'([^']*)'|([^\s]+))')
    for match in pattern.finditer(raw):
        result[match.group(1)] = match.group(2) or match.group(3) or match.group(4)
    return result
