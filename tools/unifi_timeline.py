"""Read Wazuh alerts.json JSONL and print a chronological UniFi JSONL timeline.

No network calls or configuration changes. Input may be '-' for standard input.
"""
import argparse
from datetime import datetime, timezone
import json
import sys


def timeline(lines, srcip=None, admin=None, gateway=None):
    events = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            alert = json.loads(line)
            rule = alert.get('rule', {})
            if not any(g == 'unifi' or g.startswith('unifi_')
                       for g in rule.get('groups', [])):
                continue
            data = alert.get('data', {})
            host = data.get('uni_host') or alert.get('predecoder', {}).get('hostname', '')
            actor = data.get('uni_changeagent', '')
            if srcip is not None and data.get('srcip') != srcip:
                continue
            if admin is not None and actor != admin:
                continue
            if gateway is not None and host != gateway:
                continue
            stamp = alert['timestamp']
            instant = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
            if instant.tzinfo is None:
                raise ValueError('timestamp must include a timezone')
            event = dict(timestamp=stamp, gateway=host,
                         location=alert.get('location', ''),
                         rule_id=str(rule.get('id', '')), level=rule.get('level'),
                         description=rule.get('description', ''), admin=actor,
                         srcip=data.get('srcip', ''), dstip=data.get('dstip', ''),
                         dstport=data.get('dstport', ''),
                         section=data.get('uni_changedsection', ''),
                         entry=data.get('uni_changedentry', ''),
                         changes=data.get('uni_settingschanges', ''))
            events.append((instant.astimezone(timezone.utc), event))
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise ValueError(f'Invalid alert on input line {number}: {exc}') from exc
    return [event for _, event in sorted(events, key=lambda item: item[0])]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', help='alerts.json file, or - for stdin')
    parser.add_argument('--srcip', help='exact decoded source IP')
    parser.add_argument('--admin', help='exact decoded admin name')
    parser.add_argument('--gateway', help='exact CEF host or predecoded hostname')
    args = parser.parse_args()
    try:
        if args.input == '-':
            events = timeline(sys.stdin, args.srcip, args.admin, args.gateway)
        else:
            with open(args.input, encoding='utf-8') as stream:
                events = timeline(stream, args.srcip, args.admin, args.gateway)
    except (OSError, ValueError) as exc:
        parser.exit(1, f'{exc}\n')
    for event in events:
        print(json.dumps(event, ensure_ascii=False))


if __name__ == '__main__':
    main()
