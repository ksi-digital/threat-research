rule Linux_Go_Telegram_Agent
{
    meta:
        description = "Go Linux backdoor that takes its C2 address and commands from a Telegram bot (agent_<arch> builds served from 176.65.134.119)"
        author = "KSI Digital"
        date = "2026-10-06"
        reference = "https://github.com/ksi-digital/threat-research/tree/main/telegram-go-agent"
        tlp = "clear"
        yarahub_uuid = "7f59f759-cfb0-4757-910a-8e6509053429"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "26c6d26d1544c2d99beefbb0a69dcc3d"
        yarahub_reference_link = "https://github.com/ksi-digital/threat-research/tree/main/telegram-go-agent"
    strings:
        $f1 = "main.tgGetPinned" ascii
        $f2 = "main.tgGetUpdates" ascii
        $f3 = "main.telegramFallbackLoop" ascii
        $f4 = "main.parseC2Line" ascii
        $f5 = "main.resolveC2" ascii
        $s1 = "[kworker/0:1-events]" ascii
        $s2 = "Description=System Logging Helper" ascii
        $s3 = "/getChat?chat_id=" ascii
        $s4 = "/getUpdates?limit=20" ascii
        $s5 = "SELFTEST_OK" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 20MB and
        (3 of ($f*) or (2 of ($f*) and 2 of ($s*)))
}

rule Linux_Telegram_Agent_Installer
{
    meta:
        description = "agent_i.sh shell installer that stages the Go Telegram agent"
        author = "KSI Digital"
        date = "2026-10-06"
        reference = "https://github.com/ksi-digital/threat-research/tree/main/telegram-go-agent"
        tlp = "clear"
        yarahub_uuid = "7d639ae9-2221-4c74-ab90-cdb15da2a3e7"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "e84b6e4b4b1283486267009fbddd5c7c"
        yarahub_reference_link = "https://github.com/ksi-digital/threat-research/tree/main/telegram-go-agent"
    strings:
        $hdr = "hang-proof installer for telnet-reached hosts" ascii
        $m1 = "SELFTEST_OK" ascii
        $m2 = "STAGE_OK STAGED" ascii
        $m3 = "STAGE_FAIL" ascii
        $m4 = "/tmp/.g_" ascii
        $m5 = "--selftest" ascii
        $m6 = "PROOF=" ascii
    condition:
        uint16(0) != 0x457f and filesize < 64KB and
        ($hdr or 4 of ($m*))
}
