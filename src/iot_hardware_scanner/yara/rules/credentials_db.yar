rule database_connection_string {
    meta:
        description = "Database connection string with embedded credentials"
        severity = "HIGH"
        category = "credential"

    strings:
        $mysql = /mysql:\/\/[^\s"']+:([^\s"']+)@/ nocase
        $postgres = /postgres:\/\/[^\s"']+:([^\s"']+)@/ nocase
        $mongodb = /mongodb:\/\/[^\s"']+:([^\s"']+)@/ nocase

    condition:
        any of ($*)
}