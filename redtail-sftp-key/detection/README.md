# RedTail SFTP-key loader - detection rules

| File | Engine | Detects |
| --- | --- | --- |
| [`redtail_sftp_loader.yml`](redtail_sftp_loader.yml) | Sigma | the `scp -s ... dlr@<C2>:sh` loader + `key.ppk`/`sshcfg` writes |
| [`redtail.rules`](redtail.rules) | Suricata / Snort | the dated stage-2 SFTP C2 endpoints |
| [`redtail.yar`](redtail.yar) | YARA | the RedTail shell stage: `setup.sh` / web dropper installer and the `clean.sh` cleaner |

**`redtail.yar`** covers the shell stage, not the miner binary. `RedTail_Shell_Installer` keys on the code every RedTail installer we found shares: the writable-and-executable directory hunt with a 2 MB `.testfile2` write test, the `$FOLDERS /tmp /var/tmp /dev/shm` fallback list and the `.redtail` / `redtail.<arch>` names. `RedTail_Shell_Cleaner` matches `clean.sh`, which strips download and reverse-shell lines from cron and shell profiles, stops rival miners and empties the temp directories. Tested with YARA 4.5 against 8 installers from 2024 to 2026 (our Cowrie capture and 7 more on MalwareBazaar; only 4 of the 8 are labelled RedTail there) and our captured cleaner, all matching, and against our ~720 other honeypot captures, ~260 recent MalwareBazaar Linux samples (Mirai, Gafgyt, Mozi, XorDDoS, CoinMiner, Prometei, Tsunami, shell scripts) and the system files of an Ubuntu 24.04 host, with no false positives. Both rules are on YARAify (YARAhub): [`RedTail_Shell_Installer`](https://yaraify.abuse.ch/yarahub/rule/RedTail_Shell_Installer/), [`RedTail_Shell_Cleaner`](https://yaraify.abuse.ch/yarahub/rule/RedTail_Shell_Cleaner/).

The embedded SFTP key itself has no YARA rule: in our capture it appears in the live exploit body, not as a standalone file we can test a rule against. The most durable indicator for the SFTP loader is the reused SSH **client key fingerprint**:

```
SHA256:O/at8341SoPpKvTPvMsJSgjQm30md9VTS2it25sY0vg   (comment: dlr@sftp)
```

Watch for that fingerprint, the `dlr@sftp` comment, or the `scp -s ... dlr@...:sh` loader pattern on a host. The C2 IPs rotate; treat the Suricata rules as dated indicators.

The Sigma and Suricata rules are not engine-validated here; validate in your own environment. Corrections welcome.
