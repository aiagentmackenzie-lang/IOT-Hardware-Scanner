rule ssh_private_key {
    meta:
        description = "SSH private key detected"
        severity = "HIGH"
        category = "credential"

    strings:
        $rsa = "-----BEGIN RSA PRIVATE KEY-----"
        $dsa = "-----BEGIN DSA PRIVATE KEY-----"
        $ec = "-----BEGIN EC PRIVATE KEY-----"
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----"

    condition:
        any of ($*)
}