rule telnetd_backdoor {
    meta:
        description = "Telnet daemon with no authentication in init script"
        severity = "CRITICAL"
        category = "backdoor_service"

    strings:
        $telnet1 = "telnetd" ascii nocase
        $telnet2 = "in.telnetd" ascii nocase
        $noauth1 = "-l /bin/sh" ascii
        $noauth2 = "--noauth" ascii

    condition:
        any of ($telnet*) and any of ($noauth*)
}

rule debug_shell_init {
    meta:
        description = "Debug shell spawned on serial port in init config"
        severity = "CRITICAL"
        category = "backdoor_service"

    strings:
        $shell1 = /ttyS[0-9]+::respawn:\/bin\/sh/ ascii
        $shell2 = /console::respawn:\/bin\/sh/ ascii

    condition:
        any of ($shell*)
}