# "Tadashi", an ARM IoT bot served and controlled from one host

**KSI Digital threat research | 2026-10-10 | observed 2026-10-09/10**

On 9 October 2026 two different machines logged in to our Telnet honeypot and installed the same ARM bot, which names itself Tadashi. It's served and controlled from a single host, 5.83.134[.]80: the download is on port 24331 and the command server on port 14593. We couldn't match it to a known family. MalwareBazaar has the sample with no family label. We ran it in our isolated lab, found the C2 and confirmed it live the next day. The C2 is on ThreatFox from us.

Indicators: [`iocs.csv`](iocs.csv).

## Delivery

At 09:37 UTC on 9 October, 82.8.153[.]137 (a UK broadband address, so most likely an infected device rather than the operator) logged in over Telnet as `root`. It checked the CPU type, then downloaded `http://5.83.134[.]80:24331/tadashi.arm7` into `/tmp` and started it. It then set up two ways for the bot to come back after a reboot or a cleanup:

- a crontab entry that downloads and starts the bot again every five minutes;
- a line appended to `/etc/rc.local` that does the same at boot.

At 21:48 UTC the same day a second machine, 212.40.90[.]80, ran exactly the same steps and got the same file. The login source changes, but the kit and its one host stay the same.

## The sample

`tadashi.arm7` (`a96874d6...`) is a 285,264-byte statically linked ARMv7 Linux binary. Almost none of its strings are readable on disk. When it starts, it prints a sales-pitch banner that begins `Tadashi Tv Control Unit only $24.99`, which is where the name comes from. MalwareBazaar first saw the sample on 9 October at 09:32 UTC, five minutes before it reached us, tagged `elf` and `wraith` but with no family. We haven't found a public write-up of it.

## C2

We ran the sample under ARM emulation in our lab. It contacted one address only, 5.83.134[.]80 on TCP port 14593, the same host that serves the download, and kept retrying it while the lab was offline. We reported that to ThreatFox on 9 October.

On 10 October at 03:34 UTC we ran it again with only that address reachable, for five minutes. The server accepted the connection and held it open for the whole window. Both sides exchanged small messages every few seconds, about 2.3 KB in each direction in total. We didn't decode the protocol, so we can't say what the bot was told to do.

## Detection ideas

- A crontab entry or an `/etc/rc.local` line that downloads from `5.83.134[.]80:24331` and runs the result from `/tmp`.
- Hidden executables in `/tmp` named `.bot`, `.p` or `.init`, the names the loader uses.
- Outbound TCP to `5.83.134[.]80:14593` from any device.
- On the network, Telnet logins followed by a download from an IP-only URL with a high port. Like most IoT bots, this one gets in through Telnet with default or empty passwords, so closing Telnet stops it.

## Indicators

| Indicator | Role |
| --- | --- |
| `5.83.134[.]80:14593` | C2, confirmed live ([ThreatFox 1958282](https://threatfox.abuse.ch/ioc/1958282/)) |
| `http://5.83.134[.]80:24331/tadashi.arm7` | payload download ([URLhaus](https://urlhaus.abuse.ch/host/5.83.134.80/)) |
| `a96874d62613...` | `tadashi.arm7`, ARMv7 bot ([MalwareBazaar](https://bazaar.abuse.ch/sample/a96874d626135f7cb4b1f6727275f5109442e39800299b91376fe22af870aac2/)) |
| `82.8.153[.]137`, `212.40.90[.]80` | Telnet login sources that installed it |

## Reporting status

- ThreatFox: 5.83.134[.]80:14593 (botnet_cc, family unknown, confidence 75), KSI Digital 2026-10-09. The live confirmation came a day later; ThreatFox entries can't be edited, so it's recorded here.
- URLhaus: the download URL was already queued when our gateway submitted it; it's listed under another reporter (YaRi78).
- Login sources: reported to AbuseIPDB and Spamhaus by our gateway.

## Handling

The sample was captured passively by the honeypot, which never runs downloads. It ran only in our isolated lab, whose egress fails closed. For the live run, only the C2 address and port were reachable, for five minutes, and everything else was dropped.

Contact: christophe@ksi-digital.com | abuse.ch `@ksi_digital` | Licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
