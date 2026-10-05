# XorDDoS: the 15th C2 domain the public set was missing

**KSI Digital threat research · 2026-10-05 · observed 2026-10-03/04**

A XorDDoS sample uploaded to our SSH honeypot resolved a set of 15 C2 domains. Fourteen were already on ThreatFox; one,
`srv-stat-node[.]ru`, was not on any feed and had no web hits. We reported it. This note records the chain.

Indicators: [`iocs.csv`](iocs.csv).

## Observation

On 2026-10-03 19:13 UTC an actor logged in to the Cowrie honeypot as root and uploaded, over SFTP, an ELF 32-bit i386
XorDDoS binary written to `/bin/skhqwensw`:

```
sha256 3064ca5f0f0099f9bb98503e0bcb42a2824da2be5c5c2549eea6c2511bea577a  (114,768 bytes)
```

The sample was already on MalwareBazaar (abuse_ch, 2026-10-01).

## Sandbox (offline)

We detonated it offline in the isolated lab (no internet; DNS and connections sinkholed and logged):

- self-copies to `/tmp/<random>`;
- installs `cron.hourly/gcc.sh` running every 3 minutes, with a `gcc.pid` lock — classic XorDDoS persistence;
- issued DNS lookups for **15 C2 domains** and fired ~123 SYNs to the sinkhole on TCP **1531** (its C2 port).

The 15 domains follow one naming scheme (`*-node`, `*-sync`, `*-status`, odd TLDs: `.ru .su .to .tj .am .md .vg`):

```
cloud-init-config.tj   system-patch-node.am   srv-stat-node.ru     proc-mem-status.md
metadata-fetcher.vg    legacy-data-stream.su  host-metrics-rev.su  flux-net-node.to
dist-patch-log.vg      core-sync-io.tj        stellar-sync.to      relay-agent-v4.am
nexus-bridge.to        net-sync-cache.md      db-sync-service.ru
```

Fourteen were already on ThreatFox (abuse_ch, 2026-09-29, ids 1941525–1941538). **`srv-stat-node[.]ru`** was the gap: no
ThreatFox, URLhaus or MalwareBazaar entry and no web hits.

## Indicators

| Indicator | Role |
|---|---|
| `srv-stat-node[.]ru` | XorDDoS C2 domain (previously unlisted) → ThreatFox (KSI Digital 2026-10-04) |
| `3064ca5f0f00…` | XorDDoS ELF32 i386 sample (on MalwareBazaar) |
| TCP `1531` | XorDDoS C2 port |
| `cron.hourly/gcc.sh`, `gcc.pid` | persistence artifacts |

The full 15-domain list is in [`iocs.csv`](iocs.csv) for completeness.

## Detection ideas

Ready-to-use rules are in [`detection/`](detection/). The signals they encode:

- A file in `cron.hourly` named `gcc.sh`, or a `gcc.pid` lock, on a server with no compiler-build cron.
- Outbound TCP `:1531`.
- DNS lookups for the `*-node` / `*-sync` domains above on the odd TLDs.

## Reporting status

ThreatFox: `srv-stat-node[.]ru` (botnet_cc, elf.xorddos; KSI Digital 2026-10-04). The other 14 domains and the sample were
already indexed by abuse.ch.

## Handling

Captured passively; analysed offline in an isolated lab with egress sinkholed. No C2 was contacted.

Contact: christophe@ksi-digital.com · abuse.ch `@ksi_digital` · Licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
