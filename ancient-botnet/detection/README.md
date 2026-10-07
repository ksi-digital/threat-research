# Ancient botnet - detection rules

Detection content for the [Ancient botnet](../). The YARA rule is tested against real samples (see notes); the Suricata and Sigma rules are written to standard syntax but not engine-validated here. Validate in your own environment.

| File | Engine | Detects |
| --- | --- | --- |
| [`ancient.yar`](ancient.yar) | YARA | the `persist.sh` dropper (`Ancient_Telnet_Dropper`) and the bot ELF (`Linux_Ancient_Bot`) |
| [`ancient.rules`](ancient.rules) | Suricata / Snort | the `ANCT` C2 handshake on the wire; the dated C2 and payload endpoints |
| [`ancient_host_artifacts.yml`](ancient_host_artifacts.yml) | Sigma | the `.ancient` binary and its persistence entries on a host |

## Notes

- **`Ancient_Telnet_Dropper`** matches the **dropper script**. It was tested against our three captured `persist.sh` versions and a fourth version another researcher uploaded to MalwareBazaar on 2026-10-05 (all match).
- **`Linux_Ancient_Bot`** matches the **compiled bot**. Its C2 tag, domain and port are built at runtime, so the rule keys on the persistence layer instead, which is plain text in every build: the module names `home_persist`, `cron_deb`, `android_rc` and `rc_local`, the `sysd` init script and `sys.service` user unit, and the toybox/busybox download chain. It matches all nine builds we could obtain (four x86-64, five ARMv7, 2026-10-03 to 2026-10-05). MalwareBazaar labels all nine as Mirai: Elastic's `Linux_Trojan_Mirai` signatures fire on the x86-64 builds, which is consistent with a Mirai-derived core under a custom C2 layer.
- Both rules were also run against our ~720 other honeypot captures, ~260 recent MalwareBazaar Linux samples (Mirai, Gafgyt, Mozi, XorDDoS, CoinMiner, Prometei, Tsunami, shell scripts) and the system files of an Ubuntu 24.04 host, with no false positives. Both are on YARAify (YARAhub): [`Ancient_Telnet_Dropper`](https://yaraify.abuse.ch/yarahub/rule/Ancient_Telnet_Dropper/), [`Linux_Ancient_Bot`](https://yaraify.abuse.ch/yarahub/rule/Linux_Ancient_Bot/).
- **`ancient.rules`** rule 1 is the strongest network signal: the literal `ANCT` as the first four bytes of the outbound C2 stream. It is not port-locked, since the C2 port can change. Rules 2 and 3 pin the specific `89.163.157[.]131` endpoints seen on 2026-10-05 and should be treated as dated indicators.
- **`ancient_host_artifacts.yml`** keys on the unusual `.ancient` filename and the dropper's persistence paths.

Corrections and improvements welcome - open an issue.
