rule bearer_token {
    meta:
        description = "Bearer token in configuration"
        severity = "MEDIUM"
        category = "credential"

    strings:
        $bearer = /Bearer\s+[A-Za-z0-9\-._~+/]+=*/ nocase

    condition:
        $bearer
}

rule oauth_token {
    meta:
        description = "OAuth token detected"
        severity = "MEDIUM"
        category = "credential"

    strings:
        $token = /token\s*=\s*["'][A-Za-z0-9\-._~+/]{20,}["']/ nocase

    condition:
        $token
}