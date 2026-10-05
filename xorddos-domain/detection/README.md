# XorDDoS - detection rules

| File | Engine | Detects |
|---|---|---|
| [`xorddos.rules`](xorddos.rules) | Suricata / Snort | the C2 port 1531 and the `srv-stat-node[.]ru` DNS lookup |
| [`xorddos_persistence.yml`](xorddos_persistence.yml) | Sigma | the `cron.hourly/gcc.sh` + `gcc.pid` persistence |

The ELF sample itself is already detected by public signatures - on our gateway it matches Elastic's
`Linux_Trojan_Xorddos` rule - so we do not duplicate a binary YARA rule here and instead cover the network and host
behaviour. The full C2 domain list is in the finding's [`iocs.csv`](../iocs.csv).

Not engine-validated here; validate in your own environment. Corrections welcome.
