# A broken LZRD build that sends its own encoded strings

**KSI Digital threat research | 2026-10-05 | observed 2026-10-03**

A Telnet client hit our honeypot with logins and commands that looked like noise. Decoded, they are the credential list and shell probe of an LZRD build, a Mirai variant that checks for a real shell with `/bin/busybox LZRD`. The bot sends its strings without decoding them first, so most of its logins could never work on a real device.

Indicators: [`iocs.csv`](iocs.csv).

## Observation

On 2026-10-03 between 13:25 and 13:30 UTC, `14.33.48[.]192` opened ten Telnet sessions, about 33 seconds apart. Each session tried one username and password, then sent the same five commands:

```
lghkel
zpz}ld
zalee
za
&k`g&k|zpkfq)ES[M
```

Our honeypot accepts any login, so every attempt "succeeded" and we saw the full sequence each time.

## Decoding

Each command is the intended text XORed with `0x09`:

| Sent | Decoded |
| --- | --- |
| `lghkel` | `enable` |
| `zpz}ld` | `system` |
| `zalee` | `shell` |
| `za` | `sh` |
| `` &k`g&k\|zpkfq)ES[M `` | `/bin/busybox LZRD` |

The credentials are not all encoded the same way. XORing what was sent with the readable value gives three different keys:

| Key | Logins (decoded) |
| --- | --- |
| `0xBE` | guest/1234, admin/qwerty, admin/0000, root/juantech, admin/admin, root/anko |
| `0x50` | root/cat1029, root/xc3511 |
| none | root/uClinux, admin/admin |

Mirai-family bots keep their strings XOR-encoded in the binary and decode them right before use. Here the commands come out encoded with one key and the credentials with three, and only the plain-text entries are usable. That is consistent with a build whose credential list was pasted together from builds that used different encoding keys, and whose decode step does not match any of them. We did not capture a binary, so this is inferred from the traffic alone.

## Why it matters

Not much for defenders, since this build mostly fails to log in. It is a useful reminder that encoded strings sometimes leak straight onto the wire: the five encoded commands above are a stable fingerprint for this build, even though the credentials vary.

## Detection ideas

- Telnet sessions that send `lghkel`, `zpz}ld` or `` &k`g&k|zpkfq)ES[M `` (the XOR-0x09 form of `/bin/busybox LZRD`).
- More generally, a login followed by the plain `/bin/busybox LZRD` probe.

## Handling

Observed passively in a Cowrie honeypot. No payload was downloaded and nothing was contacted.

Contact: christophe@ksi-digital.com | abuse.ch `@ksi_digital` | Licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
