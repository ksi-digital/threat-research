# RedTail: a reused SFTP client key links its web and SSH delivery

**KSI Digital threat research | 2026-10-05 | observations 2026-10-02 to 2026-10-03**

RedTail is a well-documented Linux cryptomining botnet; its PHP-CGI dropper is covered in SANS ISC diary 32936. This note does not re-describe that. It records two indicators we did not find published, offered as IOCs rather than as a new technique (corrections welcome):

1. an **embedded ed25519 SSH client key** the droppers carry to pull their next stage over SFTP, and
2. the **same key appearing in both the web dropper and the SSH-loader vector**, which ties the two to one operator.

Indicators: [`iocs.csv`](iocs.csv).

## Observation

We ran a WordPress honeypot (behind a WAF that retains request bodies) and a Cowrie SSH/Telnet honeypot.

**Web vector - 2026-10-02.** A node sending User-Agent `libredtail-http` delivered RedTail's PHP-CGI dropper to the WordPress bait. Our WAF retained the decoded dropper bodies. The stage-1 shell script carries an ed25519 private key and prefers to pull its stage-2 over SFTP (`scp -s ... dlr@<C2>:sh`), with an HTTPS download as fallback. The bait is modern PHP and was not exploitable; nothing executed. We did not fetch stage-2 (that would mean contacting the C2).

**SSH vector - 2026-10-03.** A RedTail bot logged in to the Cowrie honeypot and ran the same loader: it writes the key file and an SSH config, then pulls stage-2 from a different C2 host over SFTP with the same credentials, same HTTPS fallback. Cowrie does not emulate outbound SFTP, so again nothing was contacted.

## The linking indicator

Both vectors embed the **same** ed25519 client key:

```
SHA256:O/at8341SoPpKvTPvMsJSgjQm30md9VTS2it25sY0vg   (comment: dlr@sftp)
```

This is the botnet's own client credential for the SFTP account it downloads from. It is useful only as a pivot and a detection signal. **We did not and will not use it to connect to any attacker system** - that would be out of scope and unlawful. A web search for this fingerprint and for the two C2 hosts returned no public hits at the time of writing.

## Indicators

| Indicator | Role |
| --- | --- |
| `SHA256:O/at8341SoPpKvTPvMsJSgjQm30md9VTS2it25sY0vg` (`dlr@sftp`) | embedded SFTP client key, both vectors |
| `217.60.103[.]56:22` | stage-2 SFTP C2 (web vector), SWISSNET LLC NL |
| `217.60.102[.]5:22` | stage-2 SFTP C2 (SSH vector), sibling netblock -> ThreatFox 1948446 (KSI Digital) |
| User-Agent `libredtail-http` | RedTail self-propagating scanner/dropper |

## Detection ideas

Ready-to-use rules are in [`detection/`](detection/). The signals they encode:

- A written-out SSH private key whose fingerprint is `SHA256:O/at8341...`, or the comment `dlr@sftp`, anywhere on a host.
- `scp -s ... dlr@<ip>:sh out_sh` or an SSH config plus key written to `/dev/shm` or `/tmp` just before an outbound SSH/SFTP connection.
- Inbound requests with User-Agent `libredtail-http`.

## Reporting status

ThreatFox: `217.60.102[.]5:22` (payload_delivery, elf.redtail; KSI Digital 2026-10-03, id 1948446). The reused key and the `.103.56` host are recorded here as indicators. Fresh C2 IPs are routine for RedTail, which rotates them.

## Handling

Samples were captured passively by honeypots and reviewed offline in an isolated lab. No attacker system was contacted.

Contact: christophe@ksi-digital.com | abuse.ch `@ksi_digital` | Licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
