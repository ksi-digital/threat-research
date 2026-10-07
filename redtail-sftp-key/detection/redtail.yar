rule RedTail_Shell_Installer
{
    meta:
        description = "RedTail cryptominer shell installer (setup.sh / web dropper): finds a writable exec dir with a 2 MB test file, then runs .redtail or redtail.<arch>"
        author = "KSI Digital"
        date = "2026-10-07"
        reference = "https://github.com/ksi-digital/threat-research/tree/main/redtail-sftp-key"
        tlp = "clear"
        yarahub_uuid = "1a93b5c6-2e30-49ee-a83e-ae01a46967b0"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "224b41af1717915304b30540473b8db2"
        yarahub_reference_link = "https://github.com/ksi-digital/threat-research/tree/main/redtail-sftp-key"
        malpedia_family = "elf.redtail"
    strings:
        $n1 = ".redtail" ascii
        $n2 = "redtail.$" ascii
        $n3 = "redtail.*" ascii
        $t1 = "of=.testfile2 bs=2M count=1" ascii
        $t2 = "truncate -s 2M .testfile2" ascii
        $t3 = "-perm -u=rwx -not -path" ascii
        $t4 = "$FOLDERS /tmp /var/tmp /dev/shm" ascii
        $t5 = "grep -q \"i[3456]86\"" ascii
        $t6 = "exec 3<>\"/dev/tcp/" ascii
    condition:
        uint32(0) != 0x464c457f and filesize < 64KB and
        (1 of ($n*) and 3 of ($t*))
}

rule RedTail_Shell_Cleaner
{
    meta:
        description = "RedTail clean.sh: strips download/reverse-shell lines from cron and shell profiles, stops rival miners, empties /tmp, /var/tmp and /dev/shm"
        author = "KSI Digital"
        date = "2026-10-07"
        reference = "https://github.com/ksi-digital/threat-research/tree/main/redtail-sftp-key"
        tlp = "clear"
        yarahub_uuid = "028f0481-5af4-4829-811e-ee7864b180bb"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "2ca1a863f6a115127d623d3d181ab9b4"
        yarahub_reference_link = "https://github.com/ksi-digital/threat-research/tree/main/redtail-sftp-key"
        malpedia_family = "elf.redtail"
    strings:
        $g  = "grep -vE 'wget|curl|/dev/tcp|/tmp|\\.sh|nc|bash -i|sh -i|base64 -d'" ascii
        $c1 = "c3pool_miner" ascii
        $c2 = "clean_file ~/.bashrc" ascii
        $c3 = "chattr -ia /var/spool/cron/crontabs" ascii
        $c4 = "-mindepth 1 -maxdepth 1 -exec rm -rf -- {} +" ascii
        $c5 = "clean_file /etc/anacrontab" ascii
    condition:
        uint32(0) != 0x464c457f and filesize < 64KB and
        ($g and 2 of ($c*))
}
