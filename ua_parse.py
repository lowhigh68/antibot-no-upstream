#!/usr/bin/env python3
"""
Parse bad bot UA patterns từ nginx-ultimate-bad-bot-blocker globalblacklist.conf
Usage: python3 ua_parse.py <globalblacklist.conf> [custom.txt]
Output: JSON array to stdout

Format thực tế của file:
    "~*(?:\b)360Spider(?:\b)"    3;
    "~*(?:\b)AdsBot-Google(?:\b)" 3;
Cần strip: ~* prefix, (?:\b) wrapper, quotes
"""
import sys
import re
import json


def parse_globalblacklist(filepath):
    patterns = []
    in_ua_block = False

    with open(filepath, 'r', errors='replace') as f:
        for line in f:
            line = line.strip()

            if 'map $http_user_agent' in line:
                in_ua_block = True
                continue

            if in_ua_block:
                if line == '}':
                    in_ua_block = False
                    continue
                if not line or line.startswith('#'):
                    continue
                if line.startswith('default'):
                    continue

                # Format: "~*(?:\b)PatternName(?:\b)"   N;
                # hoặc:    ~*PatternName  N;
                # N có thể là bất kỳ số nào (1, 2, 3...)
                m = re.match(r'"?~\*(?:\(\?:\\b\))?([^"(?]+?)(?:\(\?:\\b\))?"?\s+\d+\s*;', line)
                if m:
                    pattern = m.group(1).strip().replace('\\ ', ' ')
                    if len(pattern) >= 3:
                        patterns.append(pattern)

    return sorted(set(patterns))


def parse_custom(filepath):
    patterns = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    patterns.append(line)
    except FileNotFoundError:
        pass
    return patterns


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: ua_parse.py <globalblacklist.conf> [custom.txt]", file=sys.stderr)
        sys.exit(1)

    base   = parse_globalblacklist(sys.argv[1])
    custom = parse_custom(sys.argv[2]) if len(sys.argv) > 2 else []
    merged = sorted(set(base + custom))

    print(json.dumps(merged))
    print(f"base={len(base)} custom={len(custom)} total={len(merged)}", file=sys.stderr)
