/*
   Starter YARA rules — deliberately few and deliberately broad.

   These catch the loud, high-signal things that show up in intrusion evidence:
   webshells, encoded PowerShell droppers, and known offensive tooling strings.
   They are NOT a detection suite. Point inspecthor at a real ruleset
   (`detect --yara-rules DIR`) for coverage; these exist so a fresh install
   produces something useful and so the plumbing is exercised by the tests.

   NOTE for anyone editing these: YARA's regex engine does NOT support
   non-capturing groups. Write `(a|b)`, never `(?:a|b)` — the latter fails to
   compile and takes the whole ruleset down with it.

   `severity` metadata drives the event severity: critical/high -> high,
   medium -> med, low -> info. `attack` metadata becomes validated ATT&CK ids.
*/

rule Inspecthor_Webshell_PHP
{
    meta:
        author = "inspecthor"
        description = "PHP webshell: request parameter passed straight to an executor"
        severity = "high"
        attack = "T1505.003"
    strings:
        $php = "<?php"
        $e1 = /eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $e2 = /(system|passthru|shell_exec|exec|popen)\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $e3 = /assert\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
    condition:
        $php and any of ($e1, $e2, $e3)
}

rule Inspecthor_Encoded_PowerShell
{
    meta:
        author = "inspecthor"
        description = "PowerShell invoked with a long base64 -EncodedCommand payload"
        severity = "high"
        attack = "T1059.001"
    strings:
        $ps = "powershell" nocase
        $enc = /-[eE](nc|ncoded|ncodedCommand)?\s+[A-Za-z0-9+\/=]{40,}/
    condition:
        $ps and $enc
}

rule Inspecthor_PowerShell_Downloader
{
    meta:
        author = "inspecthor"
        description = "In-memory download-and-execute pattern"
        severity = "high"
        attack = "T1105"
    strings:
        $a = "DownloadString" nocase
        $b = "Net.WebClient" nocase
        $c = "Invoke-Expression" nocase
        $d = "IEX" fullword nocase
        $e = "DownloadFile" nocase
    condition:
        ($a or $e) and ($b or $c or $d)
}

rule Inspecthor_Mimikatz_Strings
{
    meta:
        author = "inspecthor"
        description = "Mimikatz credential-dumping module strings"
        severity = "critical"
        attack = "T1003.001"
    strings:
        $a = "sekurlsa" nocase
        $b = "mimikatz" nocase
        $c = "gentilkiwi" nocase
        $d = "lsadump" nocase
        $e = "privilege::debug" nocase
    condition:
        2 of them
}

rule Inspecthor_Reverse_Shell_OneLiner
{
    meta:
        author = "inspecthor"
        description = "Common *nix reverse-shell one-liner"
        severity = "high"
        attack = "T1059.004"
    strings:
        $devtcp = "/dev/tcp/"
        $nc = /nc\s+(-[a-zA-Z]+\s+)*(\d{1,3}\.){3}\d{1,3}\s+\d{1,5}/
        $sock = "socket.socket" nocase
        $pty = "pty.spawn"
        $shi = "sh -i"
    condition:
        $devtcp or $nc or ($sock and $pty) or ($shi and $devtcp)
}

rule Inspecthor_Suspicious_Persistence_Cmd
{
    meta:
        author = "inspecthor"
        description = "Service or scheduled-task persistence created from a command line"
        severity = "medium"
        attack = "T1543.003"
    strings:
        $task = /schtasks(\.exe)?\s+\/create/ nocase
        $svc = /sc(\.exe)?\s+create/ nocase
        $run = /reg(\.exe)?\s+add.*\\CurrentVersion\\Run/ nocase
        $user = /net\s+user\s+\S+\s+\S+\s+\/add/ nocase
    condition:
        any of them
}

rule Inspecthor_Log_Clearing
{
    meta:
        author = "inspecthor"
        description = "Event log clearing — anti-forensics"
        severity = "high"
        attack = "T1070.001"
    strings:
        $a = /wevtutil(\.exe)?\s+cl/ nocase
        $b = "Clear-EventLog" nocase
        $c = /vssadmin(\.exe)?\s+delete\s+shadows/ nocase
    condition:
        any of them
}
