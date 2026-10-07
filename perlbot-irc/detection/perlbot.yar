rule PerlBot_Dred_IRC
{
    meta:
        description = "PBot-derived Perl IRC DDoS bot ('DDoS Perl IrcBot v2.0', operator nick Dred)"
        author = "KSI Digital"
        date = "2026-10-05"
        reference = "https://github.com/ksi-digital/threat-research/tree/main/perlbot-irc"
        tlp = "clear"
        yarahub_uuid = "d21056d3-dfe3-404d-ad50-187e567242d0"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "10e92cfb8e3bd97b7386e1a5e6f7dfb3"
        yarahub_reference_link = "https://github.com/ksi-digital/threat-research/tree/main/perlbot-irc"
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
