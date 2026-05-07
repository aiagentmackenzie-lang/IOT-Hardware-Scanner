rule md5_constant {
    meta:
        description = "MD5 initialization constant detected (weak hash)"
        severity = "MEDIUM"
        category = "weak_crypto"

    strings:
        $md5_const = { 67452301 efcdab89 98badcfe 10325476 }

    condition:
        $md5_const
}

rule des_weak_key {
    meta:
        description = "DES weak key constant detected"
        severity = "HIGH"
        category = "weak_crypto"

    strings:
        $des_weak1 = { 01010101 01010101 }
        $des_weak2 = { FEFEFEFE FEFEFEFE }

    condition:
        any of ($des_weak*)
}

rule rc4_implementation {
    meta:
        description = "RC4 stream cipher implementation detected"
        severity = "MEDIUM"
        category = "weak_crypto"

    strings:
        $rc4_state = { 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f }

    condition:
        $rc4_state
}