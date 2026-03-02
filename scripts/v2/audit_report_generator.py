#!/usr/bin/env python3
import sys
import json
import datetime
import shlex
import re

def parse_kv(line):
    """Parses key=value pairs from a log line (supports quoted values)."""
    data = {}
    try:
        parts = shlex.split(line.strip())
    except ValueError:
        # Keep fail-open parsing for malformed quoting in historical logs.
        parts = line.strip().split()
    for part in parts:
        if '=' in part:
            k, v = part.split('=', 1)
            data[k] = v
    return data

def parse_strict_int(value):
    """Parses canonical base-10 integers only (no plus sign, padding, underscores, spaces, or float notation)."""
    if value is None:
        raise ValueError("missing integer value")
    text = str(value)
    if not re.fullmatch(r"(?:0|-?(?:[1-9][0-9]*))", text):
        raise ValueError(f"non-canonical integer: {text}")
    return int(text)


def generate_audit_report(log_file):
    events = []
    
    # Audit-critical event types
    AUDIT_TYPES = {'resolve', 'challenge', 'slash', 'pause', 'resume', 'governance'}

    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if '[event]' in line:
                    # Extract timestamp prefix + content after [event]
                    try:
                        prefix, content = line.split('[event]', 1)
                        content = content.strip()
                        data = parse_kv(content)

                        schema = data.get('event_schema') or ''
                        if schema not in {'v1', 'llm2', 'compact'}:
                            continue

                        event_ts = prefix.strip()
                        if event_ts:
                            data['event_ts'] = event_ts

                        if data.get('event_type') in AUDIT_TYPES:
                            events.append(data)
                    except ValueError:
                        continue # Skip malformed lines

    except FileNotFoundError:
        print(f"Error: File {log_file} not found.", file=sys.stderr)
        sys.exit(1)

    # Summary statistics
    summary = {
        'generated_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'source_log': log_file,
        'total_audit_events': len(events),
        'event_counts': {},
        'financial_impact': {
            'challenger_delta_total': 0,
            'treasury_delta_total': 0
        }
    }

    for e in events:
        etype = e.get('event_type', 'unknown')
        summary['event_counts'][etype] = summary['event_counts'].get(etype, 0) + 1
        
        # Aggregate financial deltas if present and strict-canonical numeric
        try:
            summary['financial_impact']['challenger_delta_total'] += parse_strict_int(e.get('challenger_delta', 0))
        except ValueError:
            pass

        try:
            summary['financial_impact']['treasury_delta_total'] += parse_strict_int(e.get('treasury_delta', 0))
        except ValueError:
            pass

    report = {
        'meta': {
            'title': 'Trillionnium Enterprise Audit Report',
            'version': '1.0'
        },
        'summary': summary,
        'audit_log': events
    }

    return json.dumps(report, indent=2)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 audit_report_generator.py <log_file>")
        sys.exit(1)
        
    log_path = sys.argv[1]
    print(generate_audit_report(log_path))
