# UniFi detections and investigation

These additions turn a few related logs into investigation context. They do not
install blocking actions, configure UniFi, or certify Network 11 compatibility.
All new fixtures are synthetic. Native Wazuh and live-device acceptance remain
required before deployment.

## WAN drops followed by allowed traffic

| Rule | Meaning | Level |
| --- | --- | --- |
| 100160 | WAN firewall parent | 0 |
| 100161 | One inbound drop/reject with a decoded source IP | 3 |
| 100162 | One inbound allow with a decoded source IP | 3 |
| 100163 | 20 drops/rejects in 120 seconds, same source and location | 10 |
| 100164 | An allow after 100163 in the previous hour, same source and location | 12 |

Enable remote **device/firewall syslog** and logging on the relevant firewall
policies. The CEF Activity Logging feed alone does not provide the raw netfilter
allow records used here. Enable only the policies you need, then verify actual
records arrive before relying on the correlation.

The additional decoder accepts `[WAN_LOCAL-A-7]`, `[WAN_IN-D-7]`,
`[WAN_LAN-R-7]` and `[WAN_DMZ-... ]` style chains (actions A/D/R, numeric rule
suffix). It extracts source/destination IP, ports and protocol independently:
MAC, TOS, field order and empty OUT interfaces are not required. IPv6 and ICMP
records can be decoded without TCP/UDP ports. Arbitrary zone names, DNAT action
codes, and every possible firmware format are outside this selector's scope.
The existing LAN decoders and IDs are retained.

The first gate counts repeated drops, not distinct ports or completed TCP
handshakes. Retries can trigger it. The second gate means a subsequent firewall
allow was logged; a normal VPN connection can also explain this. Neither alert
proves a service was exploited. Review the policy, target service and endpoint.

`same_location` separates direct syslog exporters. If a relay or shared log file
collapses several gateways into the same Wazuh location, it cannot reliably
separate their WAN histories. Preserve a separate collection location per gateway
before using this correlation across multiple gateways. Syslog hostname alone is
not a substitute for a distinct collection location in these WAN rules.

## Administrator access followed by sensitive changes

Existing rules 100114 and 100110 now expose actor/source/config context in their
descriptions and carry `unifi_admin` groups.

| Rule | Meaning | Level |
| --- | --- | --- |
| 100140 | Config change in a selected sensitive settings section | 9 |
| 100141 | 100140 after an admin login in the previous 15 minutes | 10 |

Selected sections include Firewall, Port Forward/Forwarding, Security, VPN,
WireGuard, Admin, Traffic and Zone, including `SETTINGS_` forms. WiFi and generic
System changes retain existing treatment. New or renamed firmware section
labels must be checked against real exports.

The sequence requires the same decoded `srcip`, `uni_changeagent`, `uni_host`
and Wazuh location. A missing identity field should prevent the sequence from
firing; the individual change remains searchable. This is review context, not
an assertion of an abnormal login or unauthorized change. Legitimate administration
will also match. It does not implement trusted-admin allowlists or infer the
contents of a change from its section name.

In Threat Hunting, filter `rule.groups: unifi_admin`, sort by timestamp ascending,
and add `data.uni_changeagent`, `data.srcip`, `data.uni_host`,
`data.uni_changedsection`, `data.uni_changedentry`, `data.uni_settingschanges`
and `rule.description` columns.

For an offline timeline of a bounded export or rotated `alerts.json` file:

```bash
python3 tools/unifi_timeline.py alerts.json --admin 'Test Admin' --gateway 'Test Gateway'
python3 tools/unifi_timeline.py alerts.json --srcip 203.0.113.42
```

The tool emits chronologically sorted JSONL, normalizes timezones for ordering,
and supports stdin (`-`). It reads locally with no external API calls. Filters
are exact matches. It retains matching rows in memory: use a bounded export for
large installations. A filtered timeline is not a causal proof; matching by IP
alone does not account for NAT or DHCP address reuse. CEF host names and raw
syslog hostnames may differ; use the host actually present in each stream.

## Honeypot acceptance per VLAN

1. In UniFi, enable Honeypot on the intended supported networks. Reserve unused
   addresses outside DHCP allocation and confirm they are not used by real devices.
2. Export Security events to Wazuh and validate rule 100120 with the native suite.
3. From a test client on each intended VLAN, run the vendor's test against your
   assigned address: `curl HONEYPOT_IP:21`.
4. Confirm a live alert with rule 100120 and the correct source. Inspect available
   client alias/MAC, network and VLAN fields; firmware may omit some context.
5. Configure your chosen notification channel for rule 100120 (level 12), deliver
   a test notification and account for your own authorized scanners.

Receiving a honeypot event does not automatically configure push/email alerts in
Wazuh. Gateway flow logs also do not observe every same-VLAN L2 conversation.

## Acceptance and tuning

Run the portable tests, install on a test manager, then run `wazuh-analysisd -t`
and the native fixture/sequence runner. Check for duplicate IDs 100140–100141 and
100160–100164 in your other custom rules. Validate live events after restart.

```bash
python3 -m unittest discover -s tests -v
sudo /var/ossec/bin/wazuh-analysisd -t
# Restart the test manager only after checking its validation output.
sudo python3 tests/run_wazuh.py
```

The native runner covers order, source separation, admin/host separation and
missing admin identity. Its CLI uses one fixed location, so cross-location
isolation and expiry after 15/60 minutes need separate live/API-session testing.
The engine's processing time controls correlations, not the printed timestamp
in a replayed syslog line. Restarting the manager resets in-memory history.

## References

- [Community implementation: WAN scan → allow and security config audit](https://github.com/secopsxsaiyan/wazuh-unifi) inspired the use cases. Rule ranges, fields and implementation here belong to this repository; do not install both packs without checking collisions and decoder precedence.
- [UniFi Honeypot](https://help.ui.com/hc/en-us/articles/12569193992727-UniFi-Gateway-Honeypot).
- [UniFi System Logs & SIEM Integration](https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration).
- [Wazuh rule syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html): current-event conditions, historical conditions, source, location and dynamic-field comparisons.

Reviewed 2026-11-09. Wazuh [4.14.10](https://documentation.wazuh.com/current/release-notes/release-4-14-10.html)
includes fixes in syslog TCP and IPv4/IPv6 rule matching; use a maintained manager
and test these rules on its actual version.
