// Token rules.
//
// A protocol word is not a secret. "Bearer " is an HTTP header name that
// appears in every client library, and "token=" appears in ordinary
// configuration; both matched on a stock OpenWrt image before these rules
// required a value-shaped token after the label. The negative fixture for each
// rule is the label on its own, in a shared library's data.

rule bearer_token {
    meta:
        description = "Bearer token value in configuration"
        severity = "MEDIUM"
        category = "credential"

    strings:
        // A value, not the header name: 20+ token-alphabet characters.
        $bearer = /Bearer[ \t]+[A-Za-z0-9\-._~+\/]{20,}=*/ ascii nocase

    condition:
        $bearer
}

rule oauth_token {
    meta:
        description = "OAuth token value in configuration"
        severity = "MEDIUM"
        category = "credential"

    strings:
        $token = /token[ \t]*[=:][ \t]*["']?[A-Za-z0-9\-._~+\/]{20,}/ ascii nocase

    condition:
        $token
}
