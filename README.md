# unifi-wazuh
Custom Wazuh decoders and rules for UniFi Network devices. Parses CEF (Common Event Format) syslog events and hostapd device syslog from UniFi OS and UniFi Network applications.

Original live-device validation: UniFi OS 5.1.31 + UniFi Network 10.6.101 + Wazuh 4.14. Compatibility fixes are based on Ubiquiti documentation reviewed on 2026-10-07 and synthetic regressions; verify them with your firmware and the native Wazuh test suite before deployment.

## Events Covered

### CEF Event Rules

| Rule ID | Event | Level |
|---------|-------|-------|
| 100102 | Base UniFi event (silent parent) | 0 |
| 100103 | UniFi Console event | 3 |
| 100104 | Traffic Internal Allow (LAN→LAN) | 3 |
| 100105 | Traffic External Allow (LAN→WAN) | 3 |
| 100106 | Traffic Internal Block (LAN→LAN) | 7 |
| 100107 | Traffic External Block (LAN→WAN) | 7 |
| 100108 | Wired Client Connected | 3 |
| 100109 | Wired Client Disconnected | 3 |
| 100110 | Configuration Change | 8 |
| 100111 | IPS Threat Detected | 10 |
| 100112 | WiFi Client Connected | 3 |
| 100113 | WiFi Client Disconnected | 3 |
| 100114 | Admin Accessed UniFi | 5 |
| 100115 | Device Adopted | 5 |
| 100116 | Device Offline | 8 |
| 100117 | WiFi Client Roaming | 3 |
| 100118 | Wired Client Connected (legacy) | 3 |
| 100119 | Wired Client Disconnected (legacy) | 3 |
| 100120 | Honeypot Triggered | 12 |
| 100121 | Blocked by Firewall (CEF) | 7 |
| 100122 | WAN Failover (matched by documented event name) | 8 |
| 100123 | High Latency Detected (legacy) | 5 |
| 100124 | Packet Loss Detected (legacy) | 7 |
| 100125 | Insufficient PoE Output | 7 |
| 100126 | AP Underpowered | 5 |
| 100127 | PoE Availability Exceeded | 7 |
| 100128 | IPS Threat from Internal Host | 13 |
| 100129 | High Latency Detected | 5 |
| 100130 | Packet Loss Detected | 7 |
| 100131 | Device Update Failed | 8 |
| 100199 | Unmatched CEF Event (catch-all) | 3 |

### Hostapd Rules

| Rule ID | Event | Level |
|---------|-------|-------|
| 100200 | Hostapd grouping (silent parent) | 0 |
| 100201 | STA Associated | 3 |
| 100202 | STA Disassociated | 3 |
| 100203 | RADIUS Auth Success | 5 |
| 100204 | RADIUS Auth Failed | 8 |

### Correlation / Frequency Rules

| Rule ID | Triggers On | Threshold | Level |
|---------|------------|-----------|-------|
| 100150 | LAN block (100106) | 10 in 2 min, same src | 10 |
| 100151 | WAN block (100107) | 10 in 2 min, same src | 10 |
| 100152 | IPS threat (100111) | 5 in 5 min | 13 |
| 100153 | WiFi disconnect (100113) | 8 in 1 min, same client MAC | 8 |
| 100154 | CEF firewall block (100121) | 10 in 2 min, same source IP | 10 |
| 100210 | RADIUS fail (100204) | 5 in 2 min, same MAC | 10 |

Rules include existing compliance group labels for PCI DSS, NIST 800-53 and HIPAA. Native MITRE ATT&CK mappings are provided for honeypot/scan heuristics (100120, 100150: T1046) and repeated RADIUS failures (100210: T1110). Other `mitre_t...` groups are retained as legacy tags, not native technique mappings or proof of an attack. Compliance labels do not certify compliance.

## Installation

### Configure the log transport

In UniFi Network, go to **Integration > System Logging / SIEM**, choose **SIEM Server**, select the categories to export, and enter your Wazuh manager's address and listening port. See [Ubiquiti's current SIEM documentation](https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration). You do not need to install a Wazuh agent on the UniFi gateway.

On the Wazuh manager, add a `<remote>` syslog block **inside the existing `<ossec_config>`** in `/var/ossec/etc/ossec.conf`. [examples/ossec-unifi.conf](examples/ossec-unifi.conf) shows UDP port 514 with documentation addresses: replace the addresses and match your exporter's actual UDP/TCP transport and port. `allowed-ips` is mandatory. Allow the same traffic from the actual exporters through your network/host firewall, and avoid conflicts with another syslog listener. Preserve the existing secure agent listener. If a relay forwards logs, allow the relay's source IP instead.

For TCP and UDP simultaneously, Wazuh needs separate syslog `<remote>` blocks. See [Wazuh syslog configuration](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/syslog.html).

### Install and validate the rules

Back up existing custom rules/decoders and check for duplicate IDs, including the new `100154`, before copying these files. Copy the decoder and rules files to your Wazuh manager:

```bash
cp unifi_decoders.xml /var/ossec/etc/decoders/
cp unifi_rules.xml /var/ossec/etc/rules/
```

> **Note:** Wazuh loads rule files in alphabetical order by filename. See [RULE_LOAD_ORDER.md](RULE_LOAD_ORDER.md) before renaming files or adding your own rules.

Set the decoder and rules permissions appropriately:

```bash
chown wazuh:wazuh /var/ossec/etc/decoders/unifi_decoders.xml && chmod 660 /var/ossec/etc/decoders/unifi_decoders.xml
chown wazuh:wazuh /var/ossec/etc/rules/unifi_rules.xml && chmod 660 /var/ossec/etc/rules/unifi_rules.xml
```

Validate syntax and inspect errors/warnings **before** restarting:

```bash
/var/ossec/bin/wazuh-analysisd -t
```

Then restart the Wazuh manager:

```bash
systemctl restart wazuh-manager
```

## Testing

Use `wazuh-logtest` to validate decoder and rule matching:

```bash
/var/ossec/bin/wazuh-logtest
```

Use `wazuh-analysisd` to validate the decoders and rules:
```bash
/var/ossec/bin/wazuh-analysisd -t
```

Paste representative UniFi syslog lines to verify the expected final rule IDs and decoded fields. [tests/README.md](tests/README.md) describes the sources, portable PCRE2 checks and native regression suite:

```bash
python3 tests/test_regressions.py -v
sudo python3 tests/run_wazuh.py
```

The first command requires Python 3 and the PCRE2 8-bit shared library. It checks regex extraction and XML predicates, not Wazuh's complete runtime. The second requires an installed, running Wazuh manager with these XML files loaded, and verifies final matches and stateful correlations.

## Compatibility and operational notes

- WiFi connect/disconnect accepts both `Monitoring` and legacy `Client Devices`. Reused numeric IDs also require the expected event name. CEF firewall blocks, honeypot and WAN failover use documented event names rather than guessing a new ID. Other unknown IDs remain visible through rule `100199`; review your own captures before adding mappings.
- Selected additional documented context includes client hostname, connected/last-connected AP identity, last WiFi RSSI, WiFi band/channel/auth method, configuration changes and failover WAN name. Both `UNIFIclientIp` and `UNIFIclientIP` are supported. This is not an exhaustive parser for every UniFi CEF key.
- Standard CEF fields populate Wazuh `srcport`, `dstport` and `protocol`; the existing `srcprt`, `dstprt` and `proto` aliases are retained. Values containing spaces and the final extension field are extracted. Escaped CEF values remain escaped; no full CEF unescaping is performed.
- WiFi disconnect correlation needs `UNIFIclientMac` and counts by MAC rather than a shared or mutable alias. It is a troubleshooting heuristic: poor signal and roaming can also cause repeated disconnects.
- Raw firewall decoders remain limited to the existing `LAN_LAN` / `LAN_WAN` shapes. They do not claim coverage for every zone-based firewall, `WAN_LOCAL`, IPv6 netfilter or traffic-flow export.
- Configure notifications separately. These files do not install Active Response or block traffic. For full raw-event retention, configure [Wazuh archiving and indexing](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html), plus retention limits; alerts alone are not an archive of every received event.
- After restart, confirm live events reach the dashboard and inspect `/var/ossec/logs/ossec.log`. A passing regex test or a rule listed in the dashboard does not prove the transport is working.

## Changelog

2026-10-07:
* Accept documented `Monitoring` WiFi categories while retaining `Client Devices`.
* Bound CEF headers/keys, preserve spaced values, and extract end-of-line fields and additional documented client/AP/WAN context.
* Support the documented client IP capitalization variant and expose standard Wazuh port/protocol fields alongside legacy aliases.
* Guard reused/sub-string event IDs; recognize firewall blocks, honeypot and WAN failover by their documented names.
* Add CEF firewall block correlation and count WiFi disconnects by client MAC.
* Make hostapd association/disassociation rule predicates exclusive and add selected native MITRE mappings.
* Add synthetic fixtures, portable PCRE2 regressions, native Wazuh regressions and a syslog configuration example.

2026-09-23:
* Merged commit #6 resolving WiFi Client Roaming events appearing as Blocked by Firewall events and added rule file policies and best practices documentation from FarmhouseNetworking
* Reordered several rules to better align with top-level categories
* Updated event ID for Blocked by Firewall events and adjusted rule level to reflect that the event is no longer necessarily an IPS threat block
* Updated event ID for Device Offline events
* Added rule for Device Update Failed events
* Disabled Honeypot Triggered(ID 100120) rule as the specified event ID has most certainly been replaced - under review but should be caught by catch-all(ID 100199)

2026-09-05:
* Support for UniFi OS 5.1.31 / Network 10.6.101
* Merged commit #5 (thanks swong001) but set UNIFIsrcClientAlias/UNIFIsrcClientMac to uni_clientdev/uni_clientmac 
* Updated rule event ID's leaving previous ID's as legacy with additional for review
* Revised rule 100111(IPS Threat Detected) such that it doesn't trigger on Blocked by Firewall events
* Revised rule 100110(Configuration Change) such that it doesn't trigger on Network Accessed events
* Reordered several child decoders to better align with top-level categories
* Added new child decoders for app(Network Application Layer Protocol), direction, srcZone, dstZone, dstRegion, dstDomain, bytesSent, bytesReceived, totalBytes, wanName, srcClientIP
* Tightened up regex for certain decoders

2026-06-02:
* Fixed a couple regex mappings (thanks driemekasten)
* Updated associated rules 

2026-04-19:
* Added support for UniFi OS 5.0.16 / Network 10.2.105
* IPv6 support in CEF `src=`, `dst=`, `UNIFIclientIp=` decoders
* Broadened lookahead patterns to prevent value bleed across KV fields
* Added `UNIFIutcTime` decoder for new timestamp field
* Added 10 new KV field decoders (clientMac, networkName, networkSubnet, networkVlan, deviceName, deviceModel, deviceIp, deviceMac, duration, ipsSessionId)
* Added hostapd device syslog decoders and rules (STA association, RADIUS auth)
* Added MITRE ATT&CK mappings to all rules
* Added 14 new CEF event rules: admin access (544), device adopted/offline (200/201), WiFi roaming (304), wired client connect/disconnect (302/303), honeypot (401+Security), firewall block CEF (402), WAN failover/latency/loss (500-502), PoE events (600-602)
* Added enrichment rule for IPS threats from internal hosts (100128)
* Added catch-all rule for unmatched CEF events (100199)
* Added 5 correlation/frequency rules for scan detection, attack detection, deauth, and RADIUS brute force
* Fixed event_id 401 collision between WiFi disconnect and honeypot using category disambiguation

2025-12-22:
* Added compliance mappings to rules (PCI DSS, NIST 800-53, HIPAA)
* Renumbered rule IDs from 100002-100007 to 100102-100113
* Adjusted rule levels: base rule now silent (level 0), allow rules level 3, block rules level 7
* Added new rules: config change detection (100110), IPS threat detection (100111), WiFi client connect/disconnect (100112/100113)
* Updated tested versions to UniFi OS 4.4.9, UniFi Network 10.0.162, Wazuh 4.14

2025-12-12:
* Small fix to base in severity field

2025-10-25:
* Divided syslog traffic events based on firewall action
* Ordered key values by section
* Preliminary fields for Threat Detected and Blocked events
