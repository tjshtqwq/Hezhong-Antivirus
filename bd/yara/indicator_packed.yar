import "pe"



rule INDICATOR_EXE_Packed_ASPack {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with ASPack"
        snort2_sid = "930007-930009"
        snort3_sid = "930002"
    //strings:
    //    $s1 = { 00 00 ?? 2E 61 73 70 61 63 6B 00 00 }
    condition:
        uint16(0) == 0x5a4d and //all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".aspack"
            )
        )
}



rule INDICATOR_EXE_Packed_aPLib {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with aPLib."
    strings:
        $header = { 41 50 33 32 18 00 00 00 [0-35] 4D 38 5A 90 }
    condition:
        ((uint32(0) == 0x32335041 and uint32(24) == 0x905a384d) or (uint16(0) == 0x5a4d and $header ))
}


rule INDICATOR_EXE_Packed_Enigma {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Enigma"
        snort2_sid = "930052-930054"
        snort3_sid = "930018"
    strings:
        $s1 = ".enigma0" fullword ascii
        $s2 = ".enigma1" fullword ascii
        $s3 = ".enigma2" fullword ascii
        $s4 = ".enigma3" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".enigma0" or
                pe.sections[i].name == ".enigma1" or
                pe.sections[i].name == ".enigma2" or
                pe.sections[i].name == ".enigma3"
            )
        )
}


rule INDICATOR_MSI_EXE2MSI {
    meta:
        author = "ditekSHen"
        description = "Detects executables converted to .MSI packages using a free online converter."
        snort2_sid = "930061-930063"
        snort3_sid = "930022"
    strings:
        $winin = "Windows Installer" ascii
        $title = "Exe to msi converter free" ascii
    condition:
        uint32(0) == 0xe011cfd0 and ($winin and $title)
}

rule INDICATOR_EXE_Packed_MPress {
    meta:
        author = "ditekSHen"
        description = "Detects executables built or packed with MPress PE compressor"
        snort2_sid = "930031-930033"
        snort3_sid = "930011"
    strings:
        $s1 = ".MPRESS1" fullword ascii
        $s2 = ".MPRESS2" fullword ascii
    condition:
         uint16(0) == 0x5a4d and 1 of them or
         for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".MPRESS1" or
                pe.sections[i].name == ".MPRESS2"
            )
        )
}

rule INDICATOR_EXE_Packed_Nate {
    meta:
        author = "ditekSHen"
        description = "Detects executables built or packed with Nate packer"
        snort2_sid = "930034-930036"
        snort3_sid = "930012"
    strings:
        $s1 = "@.nate0" fullword ascii
        $s2 = "`.nate1" fullword ascii
    condition:
         uint16(0) == 0x5a4d and 1 of them or
         for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".nate0" or
                pe.sections[i].name == ".nate1"
            )
        )
}

rule INDICATOR_EXE_Packed_VMProtect {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with VMProtect."
        snort2_sid = "930049-930051"
        snort3_sid = "930017"
    strings:
        $s1 = ".vmp0" fullword ascii
        $s2 = ".vmp1" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".vmp0" or
                pe.sections[i].name == ".vmp1"
            )
        )
}


rule INDICATOR_EXE_Packed_eXPressor {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with eXPressor"
        snort2_sid = "930043-930048"
        snort3_sid = "930015-930016"
    strings:
        $s1 = "eXPressor_InstanceChecker_" fullword ascii
        $s2 = "This application was packed with an Unregistered version of eXPressor" ascii
        $s3 = ", please visit www.cgsoftlabs.ro" ascii
        $s4 = /eXPr-v\.\d+\.\d+/ ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name contains ".ex_cod"
            )
        )
}


rule INDICATOR_EXE_Packed_RLPack {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with RLPACK"
        snort2_sid = "930064-930066"
        snort3_sid = "930023"
    strings:
        $s1 = ".packed" fullword ascii
        $s2 = ".RLPack" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".RLPack"
            )
        )
}

/*
Can lead to many FPs?

rule INDICATOR_EXE_Packed_UPolyX {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with UPolyX"
    strings:
        $s1 = { 81 fd 00 fb ff ff 83 d1 ?? 8d 14 2f 83 fd fc 76 ?? 8a 02 42 88 07 47 49 75 }
        $s2 = { e2 ?? ff ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s3 = { 55 8b ec ?? 00 bd 46 00 8b ?? b9 ?? 00 00 00 80 ?? ?? 51 }
        $s4 = { bb ?? ?? ?? ?? 83 ec 04 89 1c 24 ?? b9 ?? 00 00 00 80 33 }
        $s5 = { e8 00 00 00 00 59 83 c1 07 51 c3 c3 }
        $s6 = { 83 ec 04 89 ?? 24 59 ?? ?? 00 00 00 }
    condition:
        uint16(0) == 0x5a4d and 1 of them and
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name contains "UPX"
            )
        )
}
