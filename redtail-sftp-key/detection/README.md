# RedTail SFTP-key loader - detection rules

| File | Engine | Detects |
| --- | --- | --- |
| [`redtail_sftp_loader.yml`](redtail_sftp_loader.yml) | Sigma | the `scp -s ... dlr@<C2>:sh` loader + `key.ppk`/`sshcfg` writes |
| [`redtail.rules`](redtail.rules) | Suricata / Snort | the dated stage-2 SFTP C2 endpoints |

We do **not** ship a YARA rule here: in our capture the embedded key appears in the live exploit body, not as a standalone file we can test a rule against, and we don't publish untested YARA. The most durable indicator is the reused SSH **client key fingerprint**:

```
SHA256:O/at8341SoPpKvTPvMsJSgjQm30md9VTS2it25sY0vg   (comment: dlr@sftp)
```

Watch for that fingerprint, the `dlr@sftp` comment, or the `scp -s ... dlr@...:sh` loader pattern on a host. The C2 IPs rotate; treat the Suricata rules as dated indicators.

Not engine-validated here; validate in your own environment. Corrections welcome.
