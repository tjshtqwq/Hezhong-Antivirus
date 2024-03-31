import "pe"
rule HezhongRule_Trojan_Auto_Dridex_15 {
   meta:
      description = "2021-03-10 - from files 001baacb86fbb246601d84efb03de6ce6c43df8f38ee0ca6295df79cea4e144b.dll, 01d06e88b83d9e125d52692d1c9fd83b14132ca18e09e26eacd4d23d1cd60aa7.dll, 092d83bbea7c97062c8a47fe43b310bb24f5bbdf7ee7b56905ff4d0c1ba2c648.dll, 0a39575f2b689b981194bdb3e3f77a0a25f32b133ef3b03788a7f2d6258a1fd4.dll, 0a99ecd4628570736ea356e43ce1ba2d44b48ee6361074a6bb286175d6b5083e.dll, 0acb46d52cfe766ef71483b8f3886514913a41550b63cd35fa094c971a1685e8.dll, 0b608aad17dd6f580f2cf12d94ff7f71e928f7e04d40d93a14ee46e2514e7a5e.dll, 0c2879f4c1ccc84d5d1ca64a87cf634599fc3c50d5d9f6e5e796499d9c4db592.dll, 0c3436f88eb0c6832bbcfb6fd3124492cfd6ae048ae66745b659e97abc495613.dll, 0c5cefcf3c2a93c25daa7b3f2a7c78dce84085aa610594622ef437a7181c2501.dll, 0d5fae17d99ba6ba6d83fbe60f2bb9af14daf6898180d3254fdaff67f681d68e.dll, 0d9be8b355b7160f641a8dfcf8c54300ce834baf6286f1ebbcc1db436ebef1ab.dll, 0e4374bd2820547fa1ea60e818e2375f1b300dc133e250f6cfb8b4eb5b879dc6.dll, 0fbe696d1f9ba5d738076f24d26e8aff9af731c9039f8fb21966146dacc28613.dll, 1a166b21b095d4166ac2d1f628c5d42593ccafb351682f311dbd2858c8dbdc38.dll, 1b1ff37af320a7a15fd396347f890e434d482d76bb9c3777040eee0a8b732e22.dll, 1b2e40a1a0bea7e9db83f9578490358e6e97f3657f16af32f33d31cd015797b2.dll, 1c5c7f9b8eae4c4db6e3dfa47eb6486c5b8716c3404ae54700cc7e29466495de.dll, 1c6cfa1693fdb48cf3e55ee2136d1513e99280d1db799c078c481fe75ca4ac5a.dll, 1c797b58de0bc796a9ac53006cb4ff8e8ebd625cbcd4c666e1108dd771c94306.dll, 87c800c4addd79f0825afaa265f5fd4bb6b272b41d5ecaee9834f27420d9f501.dll, 87ff34678ec876feefb10ebfe8c3d14a60c45b1a7582b7ddb4ad9dc963705ee5.dll, 89b27577c0dacaaca0106332b719d325a0418cfd9f670b5d2782eb7ac6b5b095.dll, 91e5e30eeaad526a035a367b7b66072d2d98e27f61c92e9b53c379994f8fc942.dll, 93c6c03d37087991f484f7429d6440e869477311da586c3a9d168a1e55f65a9f.dll"
      author = "Hezhong Technology"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-03-30"
      hash1 = "001baacb86fbb246601d84efb03de6ce6c43df8f38ee0ca6295df79cea4e144b"
      hash2 = "01d06e88b83d9e125d52692d1c9fd83b14132ca18e09e26eacd4d23d1cd60aa7"
      hash3 = "092d83bbea7c97062c8a47fe43b310bb24f5bbdf7ee7b56905ff4d0c1ba2c648"
      hash4 = "0a39575f2b689b981194bdb3e3f77a0a25f32b133ef3b03788a7f2d6258a1fd4"
      hash5 = "0a99ecd4628570736ea356e43ce1ba2d44b48ee6361074a6bb286175d6b5083e"
      hash6 = "0acb46d52cfe766ef71483b8f3886514913a41550b63cd35fa094c971a1685e8"
      hash7 = "0b608aad17dd6f580f2cf12d94ff7f71e928f7e04d40d93a14ee46e2514e7a5e"
      hash8 = "0c2879f4c1ccc84d5d1ca64a87cf634599fc3c50d5d9f6e5e796499d9c4db592"
      hash9 = "0c3436f88eb0c6832bbcfb6fd3124492cfd6ae048ae66745b659e97abc495613"
      hash10 = "0c5cefcf3c2a93c25daa7b3f2a7c78dce84085aa610594622ef437a7181c2501"
      hash11 = "0d5fae17d99ba6ba6d83fbe60f2bb9af14daf6898180d3254fdaff67f681d68e"
      hash12 = "0d9be8b355b7160f641a8dfcf8c54300ce834baf6286f1ebbcc1db436ebef1ab"
      hash13 = "0e4374bd2820547fa1ea60e818e2375f1b300dc133e250f6cfb8b4eb5b879dc6"
      hash14 = "0fbe696d1f9ba5d738076f24d26e8aff9af731c9039f8fb21966146dacc28613"
      hash15 = "1a166b21b095d4166ac2d1f628c5d42593ccafb351682f311dbd2858c8dbdc38"
      hash16 = "1b1ff37af320a7a15fd396347f890e434d482d76bb9c3777040eee0a8b732e22"
      hash17 = "1b2e40a1a0bea7e9db83f9578490358e6e97f3657f16af32f33d31cd015797b2"
      hash18 = "1c5c7f9b8eae4c4db6e3dfa47eb6486c5b8716c3404ae54700cc7e29466495de"
      hash19 = "1c6cfa1693fdb48cf3e55ee2136d1513e99280d1db799c078c481fe75ca4ac5a"
      hash20 = "1c797b58de0bc796a9ac53006cb4ff8e8ebd625cbcd4c666e1108dd771c94306"
      hash21 = "87c800c4addd79f0825afaa265f5fd4bb6b272b41d5ecaee9834f27420d9f501"
      hash22 = "87ff34678ec876feefb10ebfe8c3d14a60c45b1a7582b7ddb4ad9dc963705ee5"
      hash23 = "89b27577c0dacaaca0106332b719d325a0418cfd9f670b5d2782eb7ac6b5b095"
      hash24 = "91e5e30eeaad526a035a367b7b66072d2d98e27f61c92e9b53c379994f8fc942"
      hash25 = "93c6c03d37087991f484f7429d6440e869477311da586c3a9d168a1e55f65a9f"
   strings:
      $s1 = "dbnoeeuf.exe" fullword wide
      $s2 = "closeduntilgthereforeWBuild.patchiFn" fullword wide
      $s3 = "FEdownloadingEdueV" fullword wide
      $s4 = "s372hzK9times9dickhead" fullword ascii
      $s5 = "Bthemaddress" fullword wide
      $s6 = "DeveloperWonlinewithinusage" fullword wide
      $s7 = "anduisbroughtappearance" fullword wide
      $s8 = "SadMChromiumversion" fullword wide
      $s9 = "preventingtheshown,system" fullword wide
      $s10 = "p*yFtP" fullword ascii
      $s11 = "19.04.44.72" fullword wide
      $s12 = "manipulationsvfredtheHighremovedf9" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and pe.imphash() == "f51e8df6bd6c2af7857cce5930a68887" and ( 8 of them )
      ) or ( all of them )
}


