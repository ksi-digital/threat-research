rule Ancient_Telnet_Dropper
{
    meta:
        description = "Ancient botnet shell dropper (persist.sh) that installs the .ancient IoT bot"
        author = "KSI Digital"
        date = "2026-10-05"
        reference = "https://github.com/ksi-digital/threat-research/tree/main/ancient-botnet"
        tlp = "clear"
        yarahub_uuid = "b9586f13-a118-4025-b9c0-a536ab18dec1"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "402bc4899ffd26dc1306755e58d951f0"
        yarahub_reference_link = "https://github.com/ksi-digital/threat-research/tree/main/ancient-botnet"
        malpedia_family = "elf.ancient"
        // Tested against the 3 captured dropper versions (match) and ~500 other
        // honeypot samples incl. the Ancient ELF payloads (no false positives).
    strings:
        $hdr  = "ancient telnet persistence payload" ascii
        $f    = "/.ancient" ascii
        $m1   = "ANCIENT_STARTED" ascii
        $m2   = "ANCIENT_NOCONN" ascii
        $m3   = "ANCIENT_FAIL" ascii
        $port = ":8A0E" ascii            // C2 port 35342 checked in /proc/net/tcp
        $arch = "BIN=x86_64" ascii
    condition:
        // shell script (not ELF), small, self-identifying OR >=2 behaviour markers
        uint16(0) != 0x457f and filesize < 64KB and
        ($hdr or ($f and 2 of ($m1, $m2, $m3, $port, $arch)))
}

rule Linux_Ancient_Bot
{
    meta:
        description = "Ancient (ANCT) IoT bot ELF: persistence modules (home_persist, cron_deb, android_rc, rc_local), sysd init script and sys.service unit, toybox/busybox download chain. C2 is built at runtime, so the rule keys on the persistence layer."
        author = "KSI Digital"
        date = "2026-10-07"
        reference = "https://github.com/ksi-digital/threat-research/tree/main/ancient-botnet"
        tlp = "clear"
        yarahub_uuid = "89d356dd-326c-4817-9c03-6f0c476fd227"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "48f7e7cbb8fb3d869ea10c167d882780"
        yarahub_reference_link = "https://github.com/ksi-digital/threat-research/tree/main/ancient-botnet"
        malpedia_family = "elf.ancient"
    strings:
        $p1 = "home_persist" ascii
        $p2 = "cron_deb" ascii
        $p3 = "android_rc" ascii
        $p4 = "rc_local" ascii
        $s1 = "/etc/init.d/sysd" ascii
        $s2 = "# Provides: sysd" ascii
        $s3 = "/etc/profile.d/sys.sh" ascii
        $s4 = "sys-daemon.sh" ascii
        $s5 = "/.config/systemd/user/sys.service" ascii
        $s6 = "Description=System Service" ascii
        $d1 = "(toybox wget -O %s %s || busybox wget -O %s %s" ascii
        $d2 = "cp -f %s %s.new >/dev/null 2>&1 && chmod 777 %s.new" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 3MB and
        3 of ($p*) and 3 of ($s*) and 1 of ($d*)
}
