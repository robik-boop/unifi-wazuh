import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    'unifi_timeline', Path(__file__).resolve().parents[1] / 'tools/unifi_timeline.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def alert(timestamp, host='Test Gateway', actor='Test Admin', ip='192.0.2.42', group='unifi'):
    return json.dumps(dict(timestamp=timestamp, rule=dict(id='100140', level=9,
                          groups=[group], description='Synthetic event'),
                          data=dict(uni_host=host, uni_changeagent=actor, srcip=ip,
                                    uni_changedsection='Firewall', uni_settingschanges='enabled: false')))


class TimelineTests(unittest.TestCase):
    def test_sort_uses_instants_not_timestamp_strings(self):
        result = module.timeline([alert('2026-11-09T10:00:00+02:00'),
                                  alert('2026-11-09T08:30:00Z')])
        self.assertEqual(result[0]['timestamp'], '2026-11-09T10:00:00+02:00')
        self.assertEqual(result[0]['changes'], 'enabled: false')

    def test_exact_filters_exclude_other_people_and_gateways(self):
        rows = [alert('2026-11-09T08:00:00Z'),
                alert('2026-11-09T08:00:00Z', host='Other Gateway'),
                alert('2026-11-09T08:00:00Z', actor='Other Admin'),
                alert('2026-11-09T08:00:00Z', ip='192.0.2.43'),
                alert('2026-11-09T08:00:00Z', group='not_unifi')]
        self.assertEqual(len(module.timeline(rows, '192.0.2.42', 'Test Admin', 'Test Gateway')), 1)

    def test_firewall_uses_predecoded_hostname(self):
        event = json.loads(alert('2026-11-09T08:00:00Z', group='unifi_wan_firewall'))
        del event['data']['uni_host']
        event['predecoder'] = dict(hostname='test-gateway')
        self.assertEqual(module.timeline([json.dumps(event)], gateway='test-gateway')[0]['gateway'],
                         'test-gateway')

    def test_malformed_input_reports_line_number(self):
        with self.assertRaisesRegex(ValueError, 'input line 2'):
            module.timeline(['\n', '{broken'])
        with self.assertRaisesRegex(ValueError, 'timezone'):
            module.timeline([alert('2026-11-09T08:00:00')])


if __name__ == '__main__':
    unittest.main()
