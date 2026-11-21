// Cryptography evidence rules.
//
// These rules answer one question: is an implementation of a named weak
// algorithm *present* in the image? They are not evidence that the algorithm
// is reachable or in use, and the crypto check says so.
//
// Every rule pairs a structural constant with an algorithm identifier. A
// constant on its own is not an algorithm: 0x00..0x0f is an ordinary lookup
// table, eight bytes of 0x01 are ordinary data, and the ChaCha20 "expand
// 32-byte k" sigma word is a standard constant of a *strong* cipher. The
// lookalike-negative fixture for each rule is the constant alone.

rule md5_constant {
    meta:
        description = "MD5 initialisation constants next to an MD5 identifier"
        severity = "MEDIUM"
        category = "weak_crypto"
        algorithm = "MD5"
        strength = "weak"

    strings:
        $md5_const = { 67452301 efcdab89 98badcfe 10325476 }
        $md5_name  = /MD5_(Init|Update|Final|Transform)/ ascii
        $md5_sym   = "md5_" ascii

    condition:
        $md5_const and ( $md5_name or $md5_sym )
}

rule des_weak_key {
    meta:
        description = "DES weak-key table next to a DES identifier"
        severity = "MEDIUM"
        category = "weak_crypto"
        algorithm = "DES"
        strength = "weak"

    strings:
        $des_weak1 = { 01010101 01010101 }
        $des_weak2 = { FEFEFEFE FEFEFEFE }
        $des_name  = /DES_(set_key|encrypt|weak_key|set_key_unchecked)/ ascii
        $des_sym   = "des_setkey" ascii nocase

    condition:
        ( $des_weak1 or $des_weak2 ) and ( $des_name or $des_sym )
}

rule rc4_implementation {
    meta:
        description = "RC4 state table next to an RC4 identifier"
        severity = "MEDIUM"
        category = "weak_crypto"
        algorithm = "RC4"
        strength = "weak"

    strings:
        $rc4_state = { 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f }
        $rc4_name  = /RC4_(set_key|encrypt|decrypt)/ ascii
        $arc4_sym  = "arc4" ascii

    condition:
        $rc4_state and ( $rc4_name or $arc4_sym )
}
