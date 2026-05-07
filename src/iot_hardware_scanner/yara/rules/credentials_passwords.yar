rule hardcoded_password_variable {
    meta:
        description = "Hardcoded password assignment in config/script"
        severity = "HIGH"
        category = "credential"

    strings:
        $pwd1 = /password\s*=\s*["'][^"']{4,}["']/ nocase
        $pwd2 = /passwd\s*=\s*["'][^"']{4,}["']/ nocase
        $pwd3 = /pwd\s*=\s*["'][^"']{4,}["']/ nocase
        $pwd4 = /admin_password\s*=\s*["'][^"']{4,}["']/ nocase

    condition:
        any of ($pwd*)
}

rule unix_md5_hash {
    meta:
        description = "MD5 crypt hash detected (weak algorithm)"
        severity = "HIGH"
        category = "credential"

    strings:
        $md5 = /\$1\$[a-zA-Z0-9.\/]{0,8}\$[a-zA-Z0-9.\/]{22}/

    condition:
        $md5
}