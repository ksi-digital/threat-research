# KSI Digital threat research

Analyses and indicators from KSI Digital's honeypot research. Each folder covers one finding, with a write-up, an
`iocs.csv`, and defanged artifacts where useful. **Binaries are never published here**; samples are referenced by SHA-256
and can be retrieved from MalwareBazaar.

## Findings

| Date | Finding |
|---|---|
| 2026-10-05 | [ancient-botnet](ancient-botnet/) — a Linux IoT botnet with DNS-over-TLS C2 lookup and a custom `ANCT` C2 protocol |
| 2026-10-05 | [redtail-sftp-key](redtail-sftp-key/) — one reused SFTP client key links RedTail's web and SSH delivery |
| 2026-10-05 | [perlbot-irc](perlbot-irc/) — a PBot-derived Perl IRC DDoS bot ("Dred") and its IRC C2 |
| 2026-10-05 | [xorddos-domain](xorddos-domain/) — the 15th XorDDoS C2 domain the public set was missing |

## Weekly reports

[`weekly/`](weekly/) holds dated honeypot activity summaries: attack volume, top source networks, credentials tried, and
the payload servers seen that week. Latest: [2026-W40](weekly/2026-W40.md).

## How we work

A WordPress bait (behind a body-retaining WAF) and a Cowrie SSH/Telnet honeypot capture attacks. Samples are analysed
offline in an isolated Hyper-V lab whose egress is fail-closed through a WireGuard tunnel; a C2 is contacted only when
necessary to confirm it is live, briefly, with only that one destination reachable. We report vetted indicators to
ThreatFox, URLhaus, MalwareBazaar (as `@ksi_digital`), AbuseIPDB (`ksi_digital`), DShield and Spamhaus.

We aim for defensible, first-hand indicators over volume. If we get something wrong, please open an issue — corrections
are welcome.

Contact: christophe@ksi-digital.com

Content licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) unless noted otherwise.
