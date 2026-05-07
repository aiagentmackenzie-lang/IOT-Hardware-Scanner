rule bearer_token {
    meta:
        description = "Bearer token in configuration"
        severity = "MEDIUM"
        category = "credential"

    strings:
        $bearer = "Bearer " ascii nocase

    condition:
        $bearer
}

rule oauth_token {
    meta:
        description = "OAuth token detected"
        severity = "MEDIUM"
        category = "credential"

    strings:
        $token = "token=" ascii nocase

    condition:
        $token
}