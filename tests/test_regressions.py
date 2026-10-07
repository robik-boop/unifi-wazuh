"""PCRE2 and XML checks; these do NOT emulate Wazuh's rule engine."""
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET
from pcre2 import search

ROOT = Path(__file__).resolve().parents[1]
DECODERS = ET.fromstring('<root>' + (ROOT / 'unifi_decoders.xml').read_text() + '</root>')
RULES = ET.parse(ROOT / 'unifi_rules.xml').getroot()


def pattern(field):
    for decoder in DECODERS:
        if decoder.findtext('order') == field:
            return decoder.findtext('regex')
    raise KeyError(field)


def allows(rule_id, fields):
    """Check field predicates only; native tests verify final rule selection."""
    rule = RULES.find(f"rule[@id='{rule_id}']")
    return all(search(field.text, fields.get(field.get('name'), '')) is not None
               for field in rule.findall('field'))


class Regressions(unittest.TestCase):
    def test_compile_all_pcre2_expressions(self):
        for root in [DECODERS, RULES]:
            for element in root.iter():
                if element.get('type') == 'pcre2':
                    with self.subTest(pattern=element.text):
                        search(element.text, '')

    def test_rule_ids_and_dependencies(self):
        ids = [rule.get('id') for rule in RULES.findall('rule')]
        self.assertEqual(len(ids), len(set(ids)))
        for node in RULES.findall('.//if_sid') + RULES.findall('.//if_matched_sid'):
            for rule_id in node.text.replace(',', ' ').split():
                self.assertIn(rule_id, ids)

    def test_header_does_not_bleed_into_extension(self):
        text = r'0|Ubiquiti|UniFi Network|10.6.101|777|Example\|Event|2|msg=payload|with|pipes'
        self.assertEqual(search(pattern('uni_app, app_version, event_id, type, severity'), text),
                         ('UniFi Network', '10.6.101', '777', r'Example\|Event', '2'))

    def test_first_and_last_extension_fields(self):
        text = '0|Ubiquiti|UniFi Network|10.6.101|401|WiFi Client Disconnected|2|UNIFIcategory=Monitoring UNIFIhost=Office UDM Pro'
        self.assertEqual(search(pattern('uni_cat'), text), ('Monitoring',))
        self.assertEqual(search(pattern('uni_host'), text), ('Office UDM Pro',))

    def test_arbitrary_cef_keys_end_values(self):
        text = r'UNIFIhost=Office UDM Pro reason=maintenance cnt=2 UNIFIclientAlias=Laptop x\=y msg=Done'
        self.assertEqual(search(pattern('uni_host'), text), ('Office UDM Pro',))
        self.assertEqual(search(pattern('uni_reason'), text), ('maintenance',))
        self.assertEqual(search(pattern('uni_clientdev'), text), (r'Laptop x\=y',))

    def test_message_can_precede_other_fields(self):
        self.assertEqual(search(pattern('message'), 'msg=Device offline UNIFIdeviceName=Lobby AP'), ('Device offline',))

    def test_documented_client_ip_spellings_and_ipv6(self):
        for key in ['UNIFIclientIp', 'UNIFIclientIP']:
            self.assertEqual(search(pattern('uni_clientip'), key+'=2001:db8::42'), ('2001:db8::42',))

    def test_documented_disconnect_context(self):
        text = ('UNIFIlastConnectedToDeviceName=Lobby AP UNIFIlastConnectedToDeviceIp=192.0.2.5 '
                'UNIFIlastConnectedToDeviceMac=02:00:00:00:00:05 UNIFIlastConnectedToWiFiRssi=-77 '
                'UNIFIclientHostname=Test Watch')
        for field, expected in [('uni_lastdevname','Lobby AP'), ('uni_lastdevip','192.0.2.5'),
                                ('uni_lastdevmac','02:00:00:00:00:05'), ('uni_rssi','-77'),
                                ('uni_clienthostname','Test Watch')]:
            self.assertEqual(search(pattern(field), text), (expected,))

    def test_standard_fields_and_old_aliases(self):
        text = 'src=192.0.2.10 spt=12345 dst=198.51.100.20 dpt=443 proto=TCP'
        for field, expected in [('srcport','12345'),('srcprt','12345'),('dstport','443'),
                                ('dstprt','443'),('protocol','TCP'),('proto','TCP')]:
            self.assertEqual(search(pattern(field), text), (expected,))
        self.assertIsNone(search(pattern('srcip'), 'foosrc=192.0.2.10'))

    def test_wifi_categories(self):
        for category in ['Monitoring', 'Client Devices']:
            self.assertTrue(allows('100113', {'event_id':'401','type':'WiFi Client Disconnected','uni_cat':category}))
        self.assertFalse(allows('100113', {'event_id':'401','type':'Honeypot Triggered','uni_cat':'Security'}))

    def test_reused_and_substring_event_ids(self):
        self.assertTrue(allows('100117', {'event_id':'402','type':'WiFi Client Roaming'}))
        self.assertFalse(allows('100117', {'event_id':'402','type':'Blocked by Firewall'}))
        self.assertTrue(allows('100121', {'event_id':'402','type':'Blocked by Firewall'}))
        self.assertFalse(allows('100117', {'event_id':'1402','type':'WiFi Client Roaming'}))

    def test_honeypot_without_guessed_event_id(self):
        self.assertTrue(allows('100120', {'event_id':'999','type':'Honeypot Triggered','uni_cat':'Security'}))
        self.assertFalse(allows('100120', {'event_id':'401','type':'WiFi Client Disconnected','uni_cat':'Monitoring'}))

    def test_hostapd_actions_are_exclusive(self):
        self.assertTrue(allows('100202', {'uni_action':'disassociated'}))
        self.assertFalse(allows('100201', {'uni_action':'disassociated'}))

    def test_correlation_uses_cef_blocks_and_mac(self):
        self.assertEqual(RULES.find("rule[@id='100154']/if_matched_sid").text, '100121')
        self.assertIsNotNone(RULES.find("rule[@id='100154']/same_srcip"))
        self.assertEqual(RULES.find("rule[@id='100153']/same_field").text, 'uni_clientmac')

    def test_native_mitre_mapping(self):
        self.assertEqual(RULES.find("rule[@id='100210']/mitre/id").text, 'T1110')
        self.assertEqual(RULES.find("rule[@id='100120']/mitre/id").text, 'T1046')


if __name__ == '__main__':
    unittest.main()
