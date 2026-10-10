# KSI Digital threat research

Analyses and indicators from KSI Digital's honeypot research. Each folder covers one finding, with a write-up, an `iocs.csv`, and defanged artifacts where useful. **Binaries are never published here**; samples are referenced by SHA-256 and can be retrieved from MalwareBazaar.

## Findings

| Date | Finding |
| --- | --- |
| 2026-10-10 | [akuma-mips-c2](akuma-mips-c2/) - a loader host that only served us error pages; its older MIPS bot names the same host as its C2, a server nobody had listed |
| 2026-10-10 | [tadashi-arm-bot](tadashi-arm-bot/) - "Tadashi", an unnamed ARM IoT bot whose download and C2 sit on one host; C2 confirmed live |
| 2026-10-10 | [mirai-dns-xor-c2](mirai-dns-xor-c2/) - a Mirai kit that hides its C2 servers in XOR-encoded DNS A records; key recovered offline, both servers confirmed live |
| 2026-10-07 | [events-calendar-poc-tool](events-calendar-poc-tool/) - an automated tool tried the Events Calendar comment bug (CVE-2026-78265) on a 6.17.3 site and was stopped; why 6.17.4.1 is still the version to be on |
| 2026-10-06 | [telegram-go-agent](telegram-go-agent/) - a Go Linux backdoor, built for 8 CPU architectures, that reads its C2 address from a Telegram bot's pinned message |
| 2026-10-05 | [ancient-botnet](ancient-botnet/) - a Linux IoT botnet with DNS-over-TLS C2 lookup and a custom `ANCT` C2 protocol |
| 2026-10-05 | [redtail-sftp-key](redtail-sftp-key/) - one reused SFTP client key links RedTail's web and SSH delivery |
| 2026-10-05 | [perlbot-irc](perlbot-irc/) - a PBot-derived Perl IRC DDoS bot ("Dred") and its IRC C2 |
| 2026-10-05 | [xorddos-domain](xorddos-domain/) - the 15th XorDDoS C2 domain the public set was missing |
| 2026-10-05 | [lzrd-broken-build](lzrd-broken-build/) - a broken LZRD (Mirai) build that sends its XOR-encoded strings straight onto the wire |

## Detection rules

Each finding's `detection/` folder holds YARA, Suricata and Sigma rules. The YARA rules are tested against our captures, recent MalwareBazaar Linux samples and clean system files before release, and are published on [YARAify](https://yaraify.abuse.ch/user/51901/) (YARAhub, CC BY 4.0), where they run against new MalwareBazaar and YARAify uploads.

| YARA rule | Detects | File |
| --- | --- | --- |
| [`Linux_Ancient_Bot`](https://yaraify.abuse.ch/yarahub/rule/Linux_Ancient_Bot/) | Ancient bot ELF (x86-64, ARM) | [`ancient.yar`](ancient-botnet/detection/ancient.yar) |
| [`Ancient_Telnet_Dropper`](https://yaraify.abuse.ch/yarahub/rule/Ancient_Telnet_Dropper/) | Ancient `persist.sh` dropper | [`ancient.yar`](ancient-botnet/detection/ancient.yar) |
| [`RedTail_Shell_Installer`](https://yaraify.abuse.ch/yarahub/rule/RedTail_Shell_Installer/) | RedTail `setup.sh` / web dropper installer | [`redtail.yar`](redtail-sftp-key/detection/redtail.yar) |
| [`RedTail_Shell_Cleaner`](https://yaraify.abuse.ch/yarahub/rule/RedTail_Shell_Cleaner/) | RedTail `clean.sh` | [`redtail.yar`](redtail-sftp-key/detection/redtail.yar) |
| [`Linux_Go_Telegram_Agent`](https://yaraify.abuse.ch/yarahub/rule/Linux_Go_Telegram_Agent/) | Go Telegram agent ELF (8 architectures) | [`telegram_go_agent.yar`](telegram-go-agent/detection/telegram_go_agent.yar) |
| [`Linux_Telegram_Agent_Installer`](https://yaraify.abuse.ch/yarahub/rule/Linux_Telegram_Agent_Installer/) | `agent_i.sh` installer | [`telegram_go_agent.yar`](telegram-go-agent/detection/telegram_go_agent.yar) |
| [`PerlBot_Dred_IRC`](https://yaraify.abuse.ch/yarahub/rule/PerlBot_Dred_IRC/) | PBot-derived Perl IRC bot | [`perlbot.yar`](perlbot-irc/detection/perlbot.yar) |

## Consolidated indicators

All indicators across findings, machine-readable: [`iocs-all.csv`](iocs-all.csv). Methodology: [`METHODOLOGY.md`](METHODOLOGY.md).

## Weekly reports

[`weekly/`](weekly/) holds dated honeypot activity summaries: attack volume, top source networks, credentials tried, and the payload servers seen that week. Latest: [2026-W40](weekly/2026-W40.md).

## How we work

A WordPress bait (behind a body-retaining WAF) and a Cowrie SSH/Telnet honeypot capture attacks. Samples are analysed offline in an isolated Hyper-V lab whose egress is fail-closed through a WireGuard tunnel; a C2 is contacted only when necessary to confirm it is live, briefly, with only that one destination reachable. We report vetted indicators to ThreatFox, URLhaus, MalwareBazaar (as `@ksi_digital`), AbuseIPDB (`ksi_digital`), DShield and Spamhaus.

We aim for defensible, first-hand indicators over volume. If we get something wrong, please open an issue - corrections are welcome.

Contact: christophe@ksi-digital.com

Content licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) unless noted otherwise.
