# Regression tests

## Sources and scope

Reviewed on 2026-10-07:

- [Ubiquiti: System Logs & SIEM Integration](https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration): CEF layout, `Monitoring` category, client IP spelling variants, last-connected AP/RSSI, configuration and failover context. The official examples still show Network 9.3.33; this is not a claim that Ubiquiti publishes a complete current event-ID registry.
- Existing repository samples and rules for Network 10.6.101 and earlier: legacy `Client Devices`, known numeric IDs, IPS fields and hostapd.
- [Wazuh logtest](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html) and [rule syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html).

`fixtures.json` contains **synthetic regression fixtures**, including adaptations of the documented event shapes. All names, addresses and MACs are test values. The 10.6.101 header is a fixture label, not a new live-device capture or certification. Unknown IDs used for honeypot/failover demonstrate matching by the documented event name; they are not proposed real event IDs.

## Portable checks

Install Python 3 and the PCRE2 8-bit shared library (`libpcre2-8-0` on Debian/Ubuntu, `pcre2` via Homebrew on macOS), then run:

```bash
python3 tests/test_regressions.py -v
```

These checks compile the actual decoder regexes with PCRE2, verify extraction and selected rule predicates, and check XML dependencies. They **do not emulate** syslog pre-decoding, decoder precedence, rule selection, or frequency counters.

## Native Wazuh validation

On a test Wazuh manager, install the two XML files as described in the project README. Validate configuration before restarting, inspect warnings, then restart the manager so logtest loads this version. Run:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo python3 tests/run_wazuh.py
```

The runner checks final rule ID, alert level and decoder with `-U`, plus expected decoded fields. It replays same-IP/different-IP CEF blocks, changing aliases with the same MAC, duplicate aliases with different MACs, and repeated RADIUS failures in separate logtest sessions. It does not modify the manager or any configuration.

Run this native suite before deploying. A portable pass alone does not prove that the rules attach correctly or that your firmware exports every field. Collect representative logs from your own devices and check unknown events captured by rule `100199`.
