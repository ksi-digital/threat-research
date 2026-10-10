# A loader host whose bot names it as the C2 too

**KSI Digital threat research | 2026-10-10 | observed 2026-10-09/10**

Since 9 October an Azure machine has been logging in to our Telnet honeypot and trying to fetch a loader script from 85.137.53[.]167. The host never served us the script: it answered with 400 and 404 error pages. But URLhaus had an older payload from the same host, a MIPS bot labelled Mirai on MalwareBazaar. We ran that bot in our isolated lab, and its only destination was the same host, 85.137.53[.]167, on TCP port 3169. Nobody had listed that C2 before; it's now on ThreatFox from us.

Indicators: [`iocs.csv`](iocs.csv).

## What reached our honeypot

172.166.156[.]160, an address in a Microsoft Azure range, logged in to our Cowrie honeypot over Telnet as `root` with an empty password three times between 17:27 and 18:00 UTC on 9 October and again at 00:20 UTC on 10 October. Each time it ran a few quick checks on the shell, then tried to download a loader script and run it with the argument `telnet`:

- `http://85.137.53[.]167:24380/bins/telnet/wget.sh` - the server answered 404;
- `http://85.137.53[.]167:24380/bins/payloads//wget.sh` - the server answered 400.

Afterwards it listed `/tmp` and `/var/tmp` for files named `akuma_*`, which is where the name we use for this kit comes from. An address one step away, 172.166.156[.]163, showed the same login pattern for a different kit on 7 October, so the Azure machines are probably shared infrastructure for more than one operator.

## The host's history

URLhaus has four URLs on 85.137.53[.]167 from other reporters:

- 27 September: `http://85.137.53[.]167:5000/bins/client_mips`, a MIPS ELF (`9e3aa12e...`), which MalwareBazaar labels Mirai;
- 5 October: `http://85.137.53[.]167:5000/bins/o.xml`, tagged ActiveMQ, which suggests the same host also spreads through vulnerable ActiveMQ servers;
- 9 October: the two `wget.sh` URLs above.

All four are offline now, but the host kept answering on port 24380, and the Azure machine kept trying it.

## C2

We took `client_mips` from MalwareBazaar instead of contacting the host, and ran it under MIPS emulation in our lab on 10 October, fully offline. In three minutes it tried to connect to 85.137.53[.]167 on TCP port 3169 twenty-one times and contacted nothing else. So the same machine hosts the downloads and the command server. We haven't confirmed the C2 live.

## Detection ideas

- Outbound TCP to `85.137.53[.]167` on any port, but especially 3169, 5000 and 24380.
- Files named `wget.sh`, or `akuma_*`, in `/tmp` or `/var/tmp` on an IoT device or server.
- Telnet logins from `172.166.156.0/24` followed by a download from an IP-only URL.

## Indicators

| Indicator | Role |
| --- | --- |
| `85.137.53[.]167:3169` | C2 ([ThreatFox 1959712](https://threatfox.abuse.ch/ioc/1959712/)) |
| `85.137.53[.]167` | payload and loader host ([URLhaus](https://urlhaus.abuse.ch/host/85.137.53.167/)) |
| `9e3aa12ebf0d...` | `client_mips`, MIPS bot ([MalwareBazaar](https://bazaar.abuse.ch/sample/9e3aa12ebf0d32b7e315de5e0fc742c6f504e35ddedf2ba4205b9bd56ad52224/)) |
| `172.166.156[.]160` | Telnet login source |

## Reporting status

- ThreatFox: 85.137.53[.]167:3169 (botnet_cc, Mirai, confidence 75), KSI Digital 2026-10-10.
- Hosting provider (Virtual Systems, Amsterdam): reported by email, 2026-10-10.
- The two `wget.sh` URLs were already on URLhaus from another reporter when we checked.

## Handling

Our honeypot captured the login attempts passively and never runs downloads. The bot came from MalwareBazaar, not from the attacker's host, and ran in our isolated lab whose egress fails closed. The run was fully offline: no packets reached 85.137.53[.]167.

Contact: christophe@ksi-digital.com | abuse.ch `@ksi_digital` | Licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
