// Password rules.
//
// A hash-shaped string is not a stored credential unless it is in an account
// database or a configuration file; the account databases are read verbatim by
// the Unix account parser, which is the only place a stored hash has meaning.
// The old `unix_md5_hash` regex matched a hash example inside libc's data on a
// stock OpenWrt image, so it is gone: `/etc/shadow` is now the only source for
// "this account stores an MD5 hash".

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
