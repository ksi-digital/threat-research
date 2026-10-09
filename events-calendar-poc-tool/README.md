# An Events Calendar attack tool that 6.17.3 stops, and why 6.17.3 still isn't enough

**KSI Digital threat research | 2026-10-07, updated 2026-10-09 | observed 2026-10-07/08**

One address ran an automated tool against the WordPress bait on our honeypot, which runs The Events Calendar 6.17.3. The tool posts a comment on an event page that carries a serialized PHP object chain, which is the approach of CVE-2026-78265. Version 6.17.3 rejects that, so nothing ran. The tool's user agent, `Mozilla/5.0 (tec-generic-async)`, had no public hits when we searched for it, so we're publishing its fingerprints. This note sticks to indicators and detection. We don't publish the request body.

_Update 2026-10-09._ Two more addresses posted a lighter version of the same comment on 2026-10-08, without that user agent. See [More sources, a lighter variant](#more-sources-a-lighter-variant).

Indicators: [`iocs.csv`](iocs.csv).

## Observation

On 2026-10-07, `157.20.244[.]50` (AS138089, a fixed-line ISP in Indonesia) sent the same six requests twice: from 10:54:51 UTC over HTTPS and from 10:56:32 UTC over plain HTTP. Every request used the user agent `Mozilla/5.0 (tec-generic-async)` and had no referer. We haven't seen that user agent from any other address.

```
GET  /wp-json/wp/v2/tribe_events?per_page=20&_fields=id,link,comment_status
GET  /
GET  /?post_type=tribe_events
GET  /event/EVENT-SLUG/
POST /wp-comments-post.php
GET  /event/EVENT-SLUG/?unapproved=N&moderation-hash=HASH
```

The first request asks the REST API for the site's events and whether comments are open on each one. The tool then posts a comment of about 21 KB on one event and, within seconds, loads the preview link that WordPress gives a commenter whose comment is waiting for moderation. Public write-ups of these bugs describe that preview as the trigger: it renders the comment for its author before anyone has approved it, so holding comments for moderation doesn't protect a vulnerable site.

The comment starts with `Nice write-up, thanks:` and continues with a `wp:legacy-widget` block for the plugin's events list widget. The block's instance data is a serialized PHP object chain built from the plugin's own classes. The commenter name is `poc` plus six random lowercase letters, with an email address at `poc.invalid`.

## What it tries to do

We decoded the comment offline. On a site where the chain works, it would:

- run a few identification commands, in both a Windows (`cmd /c`) and a Linux form, and call `phpinfo()`
- write a one-line command webshell named `pwn_tec_` plus six hex characters, `.php`, into `wp-content/uploads/`, `wp-content/` and the web root
- create a WordPress administrator named `supper` plus six random lowercase letters, with an email address at `poc.invalid`

The names (`poc`, `pwn_tec_`, `.invalid` addresses) and the Windows and Linux commands sent together look like a generic proof-of-concept tool run as it comes, not something adjusted to the target. Two runs from one address aren't enough to say who was behind it. The address does have earlier AbuseIPDB reports from other users for web scanning in late September.

## Why it failed

The 6.17.3 changelog has one security line: "Hardened validation of copied legacy widget instances". In that version the plugin checks a widget instance before using it and drops any instance that contains an object. Our capture agrees with that. Both comments were stored and both previews returned 200, but no command ran, no file was written and no user was created. Process monitoring on the host saw only WordPress sending its moderation email.

We tie the attempt to CVE-2026-78265 (PHP object injection, 6.17.2 and earlier) because the request depends on serialized objects, and that is exactly what the 6.17.3 check refuses. We didn't run it against an older version to confirm.

## More sources, a lighter variant

On 2026-10-08 two more addresses posted the same kind of comment to the same event page. Both are at DigitalOcean (AS14061).

- `159.89.45[.]50`, 22:13 UTC: `GET /`, `GET /?post_type=tribe_events`, then the `POST /wp-comments-post.php`.
- `165.22.115[.]147`, 23:00 UTC: the `POST` only, with nothing before it. It went straight to the event the earlier runs had used.

It's the same tool family. The comment opens with the same words, carries the same `wp:legacy-widget` block for the same widget, and the commenter is again `poc` plus six letters at `poc.invalid`. Three things differ:

- The user agent. Neither used `tec-generic-async`. Each sent a different old iPod Safari string (iPhone OS 3 and 4, with `hi-IN` and `sd-IN` locales), the kind a library that randomises user agents produces.
- The size. The request body is about 1.7 KB, not 21 KB. The object chain only runs an identification command, in a Windows and a Linux form. There are no webshell or administrator-account steps and nothing in it points to another server.
- The follow-up. Neither loaded the moderation preview after posting, so on our site the comments were stored and never rendered.

The instance data is still a chain of serialized objects, so 6.17.3 refused it the same way and nothing ran. Other honeypot operators reported both addresses to AbuseIPDB the same day for web probing, so we weren't the only target.

Two addresses at one provider, about 47 minutes apart, with byte-identical request sizes, look like one operator changing addresses. Whether that is the same operator as on 2026-10-07 we can't say. What three addresses in two days do show is that this tool is in circulation and not a one-off, and that its user agent can't be relied on to spot it.

## Why 6.17.3 still isn't enough

Public advisories list two more issues on the same comment path. CVE-2026-78159 is a callable-execution path that needs no serialized objects and affects versions through 6.17.3. CVE-2026-78006 affects versions through 6.17.4. Version 6.17.4.1, released 2026-09-10, is the one that closes all three.

So a site on 6.17.3 would have survived this tool, but not necessarily the next one. Update to 6.17.4.1 or later. If you can't yet, turn off comments on event pages.

References: [CVE-2026-78265](https://www.tenable.com/cve/CVE-2026-78265), [CVE-2026-78159](https://cve.threatint.com/CVE/CVE-2026-78159), [CVE-2026-78006](https://app.opencve.io/cve/CVE-2026-78006).

## Detection ideas

- Web logs with the user agent `Mozilla/5.0 (tec-generic-async)`. Later runs used ordinary-looking mobile user agents, so its absence proves nothing.
- A `GET /wp-json/wp/v2/tribe_events` with `_fields=id,link,comment_status`, followed within seconds by a `POST /wp-comments-post.php` and a `GET` carrying `unapproved=` and `moderation-hash=` from the same client. The lighter variant skips the first and last of these.
- Comments, pending ones included, whose text contains `wp:legacy-widget`. This held for every run we saw and is the most reliable signal. Visitors have no reason to post block markup in a comment. In the database: `SELECT comment_ID FROM wp_comments WHERE comment_content LIKE '%wp:legacy-widget%'`.
- Commenters or users with an email address at `poc.invalid`.
- Files named `pwn_tec_*.php` in the web root, `wp-content/` or `wp-content/uploads/`.
- Administrator accounts named `supper` plus six lowercase letters.

If you find such a comment on a site that isn't fully patched, delete it. Don't approve or preview it, because rendering the comment is what runs the chain.

## Handling

Observed passively on a WordPress honeypot that keeps full request bodies. The request was decoded offline and never replayed. Nothing was contacted. We reported the source addresses to AbuseIPDB.

Contact: christophe@ksi-digital.com | abuse.ch `@ksi_digital` | Licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
