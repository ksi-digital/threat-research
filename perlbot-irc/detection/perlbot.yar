rule PerlBot_Dred_IRC
{
    meta:
        description = "PBot-derived Perl IRC DDoS bot ('DDoS Perl IrcBot v2.0', operator nick Dred)"
        author = "KSI Digital"
        date = "2026-10-05"
        reference = "https://github.com/ksi-digital/threat-research/tree/main/perlbot-irc"
        tlp = "clear"
        // Tested against the captured sample (match) and other honeypot samples (no false positives).
    strings:
        $b1 = "DDoS Perl IrcBot" ascii
        $b2 = "Pregatit de actiune" ascii      // PBot-lineage greeting
        $c2 = "23.95.235.108" ascii             // hard-coded IRC C2 (dated)
        $vh = "dreds.network" ascii             // IRC vhost/cloak
        $pb = "PBot" ascii
    condition:
        uint16(0) != 0x457f and filesize < 256KB and
        (2 of ($b1, $b2, $vh, $c2) or ($pb and $b2))
}
