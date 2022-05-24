/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule Maldoc_CVE_2017_11882 : Exploit {
    meta:
        description = "Detects maldoc With exploit for CVE_2017_11882"
        author = "Marc Salinas (@Bondey_m)"
        reference = "c63ccc5c08c3863d7eb330b69f96c1bcf1e031201721754132a4c4d0baff36f8"
        date = "2017-10-20"
        modified = "true"
    strings:
        $doc = "d0cf11e0a1b11ae1"
        $s0 = "Equation"
        $s1 = "1c000000020"
        $h0 = {1C 00 00 00 02 00}
    condition: 
        (uint32be(0) == 0x7B5C7274 or $doc at 0 ) and $s0 and ($h0 or $s1)
}

/*
rule Prime_Constants_long {
	meta:
		author = "_pusher_"
		description = "List of primes [long]"
		date = "2016-07"
	strings:
		$c0 = { 03 00 00 00 05 00 00 00 07 00 00 00 0B 00 00 00 0D 00 00 00 11 00 00 00 13 00 00 00 17 00 00 00 1D 00 00 00 1F 00 00 00 25 00 00 00 29 00 00 00 2B 00 00 00 2F 00 00 00 35 00 00 00 3B 00 00 00 3D 00 00 00 43 00 00 00 47 00 00 00 49 00 00 00 4F 00 00 00 53 00 00 00 59 00 00 00 61 00 00 00 65 00 00 00 67 00 00 00 6B 00 00 00 6D 00 00 00 71 00 00 00 7F 00 00 00 83 00 00 00 89 00 00 00 8B 00 00 00 95 00 00 00 97 00 00 00 9D 00 00 00 A3 00 00 00 A7 00 00 00 AD 00 00 00 B3 00 00 00 B5 00 00 00 BF 00 00 00 C1 00 00 00 C5 00 00 00 C7 00 00 00 D3 00 00 00 DF 00 00 00 E3 00 00 00 E5 00 00 00 E9 00 00 00 EF 00 00 00 F1 00 00 00 FB 00 00 00 }
	condition:
		$c0
}
*/
