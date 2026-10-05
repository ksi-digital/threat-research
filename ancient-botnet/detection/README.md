# Ancient botnet - detection rules

Detection content for the [Ancient botnet](../). The YARA rule is tested against real samples (see notes); the Suricata
and Sigma rules are written to standard syntax but not engine-validated here. Validate in your own environment.

| File | Engine | Detects |
|---|---|---|
| [`ancient.yar`](ancient.yar) | YARA | the `persist.sh` dropper (file) |
| [`ancient.rules`](ancient.rules) | Suricata / Snort | the `ANCT` C2 handshake on the wire; the dated C2 and payload endpoints |
| [`ancient_host_artifacts.yml`](ancient_host_artifacts.yml) | Sigma | the `.ancient` binary and its persistence entries on a host |

## Notes

- **`ancient.yar`** was tested against the three captured dropper versions (all match) and ~500 other honeypot
  samples including the Ancient ELF payloads themselves (no false positives). It matches the **dropper script**, not
  the compiled bot: the bot builds its `ANCT` tag, C2 domain and port at runtime, so none appear as static strings. For
  the x86-64 ELF, Elastic's `Linux_Trojan_Mirai` signatures fire, which is consistent with a Mirai-derived core under a
  custom C2 layer.
- **`ancient.rules`** rule 1 is the strongest network signal: the literal `ANCT` as the first four bytes of the
  outbound C2 stream. It is not port-locked, since the C2 port can change. Rules 2 and 3 pin the specific
  `89.163.157[.]131` endpoints seen on 2026-10-05 and should be treated as dated indicators.
- **`ancient_host_artifacts.yml`** keys on the unusual `.ancient` filename and the dropper's persistence paths.

Corrections and improvements welcome - open an issue.
