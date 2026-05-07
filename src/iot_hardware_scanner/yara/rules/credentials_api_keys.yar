rule aws_access_key {
    meta:
        description = "AWS Access Key ID detected"
        severity = "HIGH"
        category = "credential"

    strings:
        $aws = /AKIA[0-9A-Z]{16}/

    condition:
        $aws
}

rule github_personal_access_token {
    meta:
        description = "GitHub Personal Access Token"
        severity = "HIGH"
        category = "credential"

    strings:
        $ghp = /ghp_[A-Za-z0-9_]{36}/

    condition:
        $ghp
}

rule stripe_secret_key {
    meta:
        description = "Stripe Secret Key"
        severity = "HIGH"
        category = "credential"

    strings:
        $sk = /sk_live_[0-9a-zA-Z]{24,}/

    condition:
        $sk
}