# PerlBot "Dred" - detection rules

| File | Engine | Detects |
| --- | --- | --- |
| [`perlbot.yar`](perlbot.yar) | YARA | the Perl bot script |
| [`perlbot.rules`](perlbot.rules) | Suricata / Snort | the IRC C2 endpoint and a JOIN to channel `#new` |

- **`perlbot.yar`** was tested against the captured sample (`a37649842a47b845...`, match) and ~500 other honeypot samples (no false positives).
- **`perlbot.rules`** rule 1 pins the dated C2 `23.95.235[.]108`; rule 2 is a generic IRC `JOIN #new`, suitable only where IRC is otherwise unexpected.
- The YARA rules are also on YARAify (YARAhub), where they run against new MalwareBazaar and YARAify uploads: [`PerlBot_Dred_IRC`](https://yaraify.abuse.ch/yarahub/rule/PerlBot_Dred_IRC/).

Validate in your own environment. Corrections welcome.
