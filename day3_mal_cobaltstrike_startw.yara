rule MAL_CobaltStrike_StartW {
meta:
    author = "m4nbat"
    description = "rule designed to match strings commonly associated with Cobalt Strike"
    status = "experimental"
    date = "2024-04-30"
strings:
    $a = "StartW" 
    $b1 = "beacon.dll"  fullword        
    $b2 = "beacon.x86.dll" fullword        
    $b3 = "beacon.x64.dll" fullword
    $z = "rule MAL_CobaltStrike"
    condition:
    filesize < 5MB and $a and 1 of ($b*) and not $z
}
