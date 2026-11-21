// Private-key rules.
//
// A PEM *header* is parser data: mbedTLS and OpenSSL both carry the literal
// "-----BEGIN RSA PRIVATE KEY-----" in their source so they can recognise it,
// and that is what matched on a stock OpenWrt image. A finding therefore
// requires key material: a header, at least 64 base64 characters, and the
// matching END line. The lookalike-negative fixture is the header alone.

rule ssh_private_key {
    meta:
        description = "SSH private key with key material"
        severity = "HIGH"
        category = "credential"

    strings:
        $rsa_begin   = "-----BEGIN RSA PRIVATE KEY-----"
        $dsa_begin   = "-----BEGIN DSA PRIVATE KEY-----"
        $ec_begin    = "-----BEGIN EC PRIVATE KEY-----"
        $ssh_begin   = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $enc_begin   = "-----BEGIN ENCRYPTED PRIVATE KEY-----"
        $body        = /[A-Za-z0-9+\/=\r\n]{64,}/
        $rsa_end     = "-----END RSA PRIVATE KEY-----"
        $dsa_end     = "-----END DSA PRIVATE KEY-----"
        $ec_end      = "-----END EC PRIVATE KEY-----"
        $ssh_end     = "-----END OPENSSH PRIVATE KEY-----"
        $enc_end     = "-----END ENCRYPTED PRIVATE KEY-----"

    condition:
        ( $rsa_begin and $rsa_end or
          $dsa_begin and $dsa_end or
          $ec_begin  and $ec_end  or
          $ssh_begin and $ssh_end or
          $enc_begin and $enc_end ) and $body
}
