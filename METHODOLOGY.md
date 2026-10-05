# Methodology

How KSI Digital captures and analyses the activity in this repository. This describes the approach, not the live configuration; specific hosts, keys and addresses of our own infrastructure are deliberately omitted.

## Sensors

- **WordPress bait** - a web application with deliberately outdated, known-vulnerable plugins, behind a web application firewall configured to **retain full request bodies**. This captures exploit attempts and their payloads, including the base64/encoded droppers that CVE exploitation delivers.
- **Cowrie SSH/Telnet honeypot** - a medium-interaction honeypot that accepts logins, records the commands attackers run, and saves every file they download or upload. Most traffic is automated IoT-botnet brute force and loader activity.
- Supporting telemetry: network flow logging and host syscall monitoring to confirm what did and did not execute.

The sensor runs continuously so capture does not depend on an analyst being present. Collected data is kept raw; all analysis happens off the sensor.

## Analysis

Samples are examined in an **isolated sandbox** on a separate machine:

- The sandbox VM has no route to any production network and no shared folders. It is reset to a clean snapshot after every run.
- All of its traffic passes through a dedicated router VM whose egress is **fail-closed** through an encrypted tunnel: if the tunnel drops, nothing leaves. The router logs every DNS query and connection and blocks everything not explicitly allowed.
- The **default is fully offline.** The sandbox records what the sample _tries_ to do - the names it resolves, the addresses and ports it reaches for - without those connections completing.
- A **C2 is contacted only when necessary to confirm it is live**, for a short, time-boxed window, with only that single destination reachable and all scanning and attack traffic still blocked. This is decided per sample.

We never connect to attacker infrastructure outside the sandbox, never reuse harvested credentials or keys, and never scan or probe third-party hosts.

## Reporting

Indicators are checked against existing feeds before submission, so we report what is genuinely new rather than duplicating others. Vetted indicators go to ThreatFox, URLhaus and MalwareBazaar (as `@ksi_digital`), AbuseIPDB (`ksi_digital`), SANS ISC / DShield and Spamhaus. Confidence reflects how we observed each indicator: an address a sample merely resolved is reported more cautiously than a C2 we watched complete a handshake.

## Publishing

In this repository:

- **Binaries are never published.** Samples are referenced by SHA-256 and are retrievable from MalwareBazaar.
- **Scripts are defanged**: every line commented out, URLs and addresses rewritten (`hxxp`, `[.]`), with a "do not run" header.
- Our own sensor addresses, keys and host details are kept out.

## Caveats

"Not found publicly" is not the same as "novel" - we say when we have simply not located prior reporting, and welcome corrections. Fresh C2 IPs are routine for these families, which rotate infrastructure; dated indicators are labelled as such.
