# Go Telegram agent - detection rules

| File | Engine | Detects |
| --- | --- | --- |
| [`telegram_go_agent.yar`](telegram_go_agent.yar) | YARA | the `agent_<arch>` Go builds (ELF) and the `agent_i.sh` installer (shell) |
| [`telegram_go_agent_host.yml`](telegram_go_agent_host.yml) | Sigma | the fake `systemd-logind.service` user unit and the staged `/tmp/.g_*` files |

## Notes

- **`telegram_go_agent.yar`** was run with YARA 4 against all eight captured builds and both installer versions (all match) and against the 39,822 other files our honeypots have collected (no false positives). The ELF rule keys on Go function names (`main.tgGetPinned`, `main.telegramFallbackLoop`, `main.parseC2Line` ...) that survive in the stripped builds, plus fixed strings like `[kworker/0:1-events]` and `Description=System Logging Helper`. A rebuild with renamed functions would evade it.
- **`telegram_go_agent_host.yml`** is written to standard Sigma syntax but not engine-validated here.
- We don't ship a network rule. The only traffic is TLS to `api.telegram.org`, which is too common to alert on by itself; treat it as a hunting lead on servers that have no reason to talk to Telegram.

Validate in your own environment. Corrections welcome - open an issue.
