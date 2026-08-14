#Requires -Version 5.1
<#
.SYNOPSIS
    Redirects network traffic to 127.0.0.1 entirely from userland - no Administrator,
    no hosts file, no routing table, no netsh, no firewall rules.

.DESCRIPTION
    THE HARD WAY. Every easy mechanism for redirecting traffic on Windows requires
    elevation, so all of them are off the table:

        C:\Windows\System32\drivers\etc\hosts   -> needs admin (file ACL)
        route add / netsh interface ipv4        -> needs admin
        netsh advfirewall / WFP filters         -> needs admin
        Set-DnsClientServerAddress              -> needs admin
        Add-DnsClientNrptRule (NRPT)            -> needs admin
        System.Net.HttpListener on :80          -> needs admin (http.sys URL ACL)

    What is left is the userland interception path, which this script builds from
    scratch out of raw sockets:

      1. INTERCEPTING PROXY. A hand-rolled HTTP/1.1 proxy is stood up on
         127.0.0.1:8080 using a raw System.Net.Sockets.TcpListener. It speaks both
         absolute-form HTTP ("GET http://host/path") and the CONNECT method used for
         TLS. For every connection it extracts the destination authority, runs it
         through the rule engine, and dials 127.0.0.1 instead of the real host when a
         rule matches. Non-matching traffic is tunnelled through untouched, so "all
         traffic" really does flow through the redirector.

         Note the deliberate choice of TcpListener over HttpListener: HttpListener is
         backed by the http.sys kernel driver and requires an admin-registered URL
         ACL. A raw TCP socket has no such requirement, and Windows - unlike Unix -
         does not reserve ports below 1024 for privileged users. That single fact is
         what makes the whole no-admin approach viable.

      2. USER-SCOPE PROXY REGISTRATION. The proxy is published to WinINET/WinHTTP via
         HKEY_CURRENT_USER, which the user owns and can write without elevation. The
         previous settings are checkpointed to a state file and restored on exit.
         wininet.dll!InternetSetOption is P/Invoked so already-running applications
         pick up the change without a restart.

      3. DNS SERVER. An optional authoritative-ish DNS server binds UDP 127.0.0.1:53
         (again: no admin needed to bind low ports on Windows). DNS wire format is
         parsed and synthesised by hand - header flags, QNAME label decompression,
         answer records with a 0xC00C name pointer. Matching names get A 127.0.0.1 /
         AAAA ::1; everything else is relayed to an upstream resolver.

      4. SINK. An optional listener on the loopback ports so redirected traffic lands
         on something that answers instead of a closed port.

    Concurrency is a RunspacePool whose InitialSessionState carries the shared rule
    engine and a synchronized context hashtable, so every worker thread sees the same
    live rule set.

.PARAMETER Mode
    Run      - start the redirector (default)
    Stop     - restore proxy settings from the checkpoint file (crash recovery)
    Status   - report current settings and listener state
    SelfTest - exercise the rule engine with assertions, no sockets opened

.PARAMETER Redirect
    One or more rules. See -RuleFile for the syntax.

.PARAMETER RuleFile
    Path to a rules file. Blank lines and '#' comments ignored. Syntax:

        example.com                     exact hostname -> 127.0.0.1 (same port)
        *.tracker.net                   wildcard; also matches the bare apex
        api.example.com:443             only when the port is 443
        93.184.216.34                   exact IPv4 literal
        10.20.0.0/16                    CIDR range
        api.example.com => 127.0.0.1:9000    explicit target
        stage.example.com => :8443           target port only
        legacy.example.com => 3000           bare port

    '=>' , '->' and '=' are interchangeable as the target separator.

.PARAMETER CatchAll
    Send EVERY destination to 127.0.0.1, not just rule matches. Rules still win for
    per-host port mapping.

.EXAMPLE
    .\Invoke-LoopbackRedirect.ps1 -Redirect 'ads.example.com','*.tracker.net' -Sink

.EXAMPLE
    .\Invoke-LoopbackRedirect.ps1 -Redirect 'api.prod.example.com => 127.0.0.1:9000'

.EXAMPLE
    .\Invoke-LoopbackRedirect.ps1 -CatchAll -Sink -LogTraffic

.EXAMPLE
    .\Invoke-LoopbackRedirect.ps1 -Mode SelfTest
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [ValidateSet('Run', 'Stop', 'Status', 'SelfTest')]
    [string] $Mode = 'Run',

    [string[]] $Redirect = @(),

    [string] $RuleFile,

    [ValidateRange(1, 65535)]
    [int] $ProxyPort = 8080,

    [switch] $CatchAll,

    [switch] $EnableDnsServer,

    [ValidateRange(1, 65535)]
    [int] $DnsPort = 53,

    [string] $UpstreamDns = '1.1.1.1',

    [switch] $Sink,

    [int[]] $SinkPorts = @(80, 8000),

    [switch] $NoSystemProxy,

    [string] $ProxyBypass = '<local>',

    [ValidateRange(2, 256)]
    [int] $MaxThreads = 48,

    [switch] $LogTraffic,

    [int] $RunSeconds = 0
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# PS 5.1 does not define $IsWindows, so probe the environment instead.
$script:OnWindows = ($env:OS -eq 'Windows_NT')
$script:StateRoot = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { [IO.Path]::GetTempPath() }
$script:StateFile = Join-Path $script:StateRoot 'LoopbackRedirect.state.json'
$script:RegPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

#region ------------------------------------------------------------ rule engine
# These functions are injected into every worker runspace via InitialSessionState,
# so they must be self-contained: no reliance on script-scope state, no cmdlets that
# would drag in extra module load cost per connection.

function ConvertTo-IPv4UInt32 {
    <# Pack a dotted-quad into a big-endian uint32 for mask arithmetic. #>
    param([Parameter(Mandatory)][System.Net.IPAddress] $Address)
    $b = $Address.GetAddressBytes()
    if ($b.Length -ne 4) { return $null }
    return [uint32](([uint32]$b[0] -shl 24) -bor ([uint32]$b[1] -shl 16) -bor ([uint32]$b[2] -shl 8) -bor [uint32]$b[3])
}

function New-RedirectRule {
    <#
        Compile one line of rule text into a match object. Parsing is done once at
        startup so the hot path is pure comparison.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string] $Line)

    if ($null -eq $Line) { return $null }
    $text = $Line.Trim()
    if (-not $text -or $text.StartsWith('#') -or $text.StartsWith(';')) { return $null }
    # Strip a trailing inline comment. Leading whitespace before the marker is
    # required so a '#' belonging to the rule itself would be left alone.
    $text = ($text -replace '\s+[#;].*$', '').Trim()
    if (-not $text) { return $null }

    # Split the optional target off the right-hand side.
    $left = $text
    $right = $null
    $sep = [regex]::Match($text, '\s*(=>|->|=)\s*')
    if ($sep.Success) {
        $left = $text.Substring(0, $sep.Index).Trim()
        $right = $text.Substring($sep.Index + $sep.Length).Trim()
    }
    if (-not $left) { return $null }

    $targetHost = $null
    $targetPort = 0
    if ($right) {
        if ($right -match '^\d{1,5}$') {
            $targetPort = [int]$right
        }
        elseif ($right -match '^:(\d{1,5})$') {
            $targetPort = [int]$Matches[1]
        }
        elseif ($right -match '^(?<h>[^:]+):(?<p>\d{1,5})$') {
            $targetHost = $Matches['h']
            $targetPort = [int]$Matches['p']
        }
        else {
            $targetHost = $right
        }
        if ($targetPort -lt 0 -or $targetPort -gt 65535) {
            throw "Rule '$text' has an out-of-range target port."
        }
    }

    # Peel an optional ':port' qualifier off the pattern (IPv4 and hostnames have no
    # colons of their own, so an unambiguous split).
    $matchPort = 0
    $pattern = $left
    if ($left -notmatch '/' -and $left -match '^(?<p>[^:]+):(?<port>\d{1,5})$') {
        $pattern = $Matches['p']
        $matchPort = [int]$Matches['port']
    }
    $pattern = $pattern.ToLowerInvariant()

    $rule = [pscustomobject]@{
        Text       = $text
        Kind       = 'Host'
        Pattern    = $pattern
        Bare       = $null
        Port       = $matchPort
        Network    = [uint32]0
        Mask       = [uint32]0
        TargetHost = $targetHost
        TargetPort = $targetPort
    }

    if ($pattern -match '^(?<net>\d{1,3}(\.\d{1,3}){3})/(?<len>\d{1,2})$') {
        $netIp = $null
        if (-not [System.Net.IPAddress]::TryParse($Matches['net'], [ref]$netIp)) {
            throw "Rule '$text' has an invalid CIDR network address."
        }
        $prefix = [int]$Matches['len']
        if ($prefix -gt 32) { throw "Rule '$text' has an invalid CIDR prefix length." }

        # Build the mask in 64-bit then truncate. Two traps here: shifting a uint32
        # left in PowerShell promotes to int and sign-extends on the top bit, and the
        # literal 0xFFFFFFFF is typed as Int32 - which makes it -1, not 4294967295.
        # Hence the explicit decimal constant.
        $allOnes = [uint64]4294967295
        $mask = if ($prefix -eq 0) { [uint32]0 }
        else { [uint32](($allOnes -shl (32 - $prefix)) -band $allOnes) }

        $rule.Kind = 'Cidr'
        $rule.Mask = $mask
        $rule.Network = [uint32]((ConvertTo-IPv4UInt32 -Address $netIp) -band $mask)
        return $rule
    }

    $ipTest = $null
    if ([System.Net.IPAddress]::TryParse($pattern, [ref]$ipTest)) {
        $rule.Kind = 'Ip'
        $rule.Pattern = $ipTest.ToString()
        return $rule
    }

    # '*.example.com' should also match 'example.com' itself - that is almost always
    # what the person writing the rule meant.
    if ($pattern.StartsWith('*.')) { $rule.Bare = $pattern.Substring(2) }
    return $rule
}

function Test-RuleMatch {
    param($Rule, [string] $TargetHost, [int] $TargetPort)

    if ($Rule.Port -gt 0 -and $Rule.Port -ne $TargetPort) { return $false }
    $h = $TargetHost.ToLowerInvariant().TrimEnd('.')

    switch ($Rule.Kind) {
        'Ip' { return ($h -eq $Rule.Pattern) }
        'Cidr' {
            $ip = $null
            if (-not [System.Net.IPAddress]::TryParse($h, [ref]$ip)) { return $false }
            if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
            $b = $ip.GetAddressBytes()
            $v = [uint32](([uint32]$b[0] -shl 24) -bor ([uint32]$b[1] -shl 16) -bor ([uint32]$b[2] -shl 8) -bor [uint32]$b[3])
            return (([uint32]($v -band $Rule.Mask)) -eq $Rule.Network)
        }
        default {
            if ($h -like $Rule.Pattern) { return $true }
            if ($Rule.Bare -and $h -eq $Rule.Bare) { return $true }
            return $false
        }
    }
    return $false
}

function Resolve-Destination {
    <# First matching rule wins; -CatchAll is the fallback. #>
    param([string] $TargetHost, [int] $TargetPort, $Ctx)

    foreach ($rule in $Ctx.Rules) {
        if (Test-RuleMatch -Rule $rule -TargetHost $TargetHost -TargetPort $TargetPort) {
            return [pscustomobject]@{
                Host       = $(if ($rule.TargetHost) { $rule.TargetHost } else { '127.0.0.1' })
                Port       = $(if ($rule.TargetPort -gt 0) { $rule.TargetPort } else { $TargetPort })
                Redirected = $true
                Rule       = $rule.Text
            }
        }
    }
    if ($Ctx.CatchAll) {
        return [pscustomobject]@{ Host = '127.0.0.1'; Port = $TargetPort; Redirected = $true; Rule = '(catch-all)' }
    }
    return [pscustomobject]@{ Host = $TargetHost; Port = $TargetPort; Redirected = $false; Rule = $null }
}

function Add-Counter {
    <# Interlocked cannot take a [ref] to a hashtable member, so lock the SyncRoot. #>
    param($Ctx, [string] $Name)
    [System.Threading.Monitor]::Enter($Ctx.Counters.SyncRoot)
    try { $Ctx.Counters[$Name] = [int]$Ctx.Counters[$Name] + 1 }
    finally { [System.Threading.Monitor]::Exit($Ctx.Counters.SyncRoot) }
}

function Write-Log {
    <# Workers never touch the console directly; the main loop drains this queue. #>
    param($Ctx, [string] $Level, [string] $Message)
    $stamp = (Get-Date).ToString('HH:mm:ss.fff')
    $Ctx.Log.Enqueue("$stamp|$Level|$Message")
}

function Find-HeaderEnd {
    <#
        Locate the end of an HTTP message head inside a byte buffer. Returns the index
        one past the terminator, or -1. Tolerates bare LF LF from sloppy clients.
    #>
    param([byte[]] $Buffer, [int] $Length)
    for ($i = 0; $i -lt $Length; $i++) {
        if ($Buffer[$i] -ne 10) { continue }
        if ($i -ge 3 -and $Buffer[$i - 1] -eq 13 -and $Buffer[$i - 2] -eq 10 -and $Buffer[$i - 3] -eq 13) { return $i + 1 }
        if ($i -ge 1 -and $Buffer[$i - 1] -eq 10) { return $i + 1 }
    }
    return -1
}

function Copy-Duplex {
    <#
        Pump bytes both ways until either direction closes. This is the byte-for-byte
        tunnel that makes CONNECT (and therefore TLS) work without decrypting
        anything - the proxy never sees inside the session, it only chooses which
        socket the ciphertext lands on.
    #>
    param($StreamA, $StreamB, [int] $IdleMs = 300000)
    try {
        $t1 = $StreamA.CopyToAsync($StreamB)
        $t2 = $StreamB.CopyToAsync($StreamA)
        [void][System.Threading.Tasks.Task]::WaitAny(@($t1, $t2), $IdleMs)
        [void][System.Threading.Tasks.Task]::WaitAll(@($t1, $t2), 2000)
    }
    catch { }   # a reset from either end is a normal way for a tunnel to end
}
#endregion

#region -------------------------------------------------- user-scope proxy config
function Update-WinInetSettings {
    <#
        Tell WinINET its configuration changed so live processes re-read HKCU without
        being restarted. INTERNET_OPTION_SETTINGS_CHANGED = 39, _REFRESH = 37.
    #>
    if (-not $script:OnWindows) { return }
    try {
        if (-not ('LoopbackRedirect.WinInet' -as [type])) {
            Add-Type -Namespace 'LoopbackRedirect' -Name 'WinInet' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("wininet.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
public static extern bool InternetSetOption(System.IntPtr hInternet, int dwOption, System.IntPtr lpBuffer, int dwBufferLength);
'@
        }
        [void][LoopbackRedirect.WinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
        [void][LoopbackRedirect.WinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
    }
    catch {
        Write-Warning "Could not notify WinINET of the settings change: $($_.Exception.Message)"
    }
}

function Get-RegValueOrNull {
    param([string] $Name)
    try { return (Get-ItemProperty -Path $script:RegPath -Name $Name -ErrorAction Stop).$Name }
    catch { return $null }
}

function Register-UserProxy {
    <#
        Point WinINET at our listener. HKCU is writable by its owner, so no elevation
        is involved anywhere in this function.
    #>
    param([string] $Server, [string] $Bypass)
    if (-not $script:OnWindows) {
        Write-Warning 'Not running on Windows - skipping system proxy registration.'
        return
    }

    $checkpoint = [pscustomobject]@{
        SavedAtUtc    = (Get-Date).ToUniversalTime().ToString('o')
        ProxyEnable   = Get-RegValueOrNull 'ProxyEnable'
        ProxyServer   = Get-RegValueOrNull 'ProxyServer'
        ProxyOverride = Get-RegValueOrNull 'ProxyOverride'
        Pid           = $PID
    }
    $checkpoint | ConvertTo-Json | Set-Content -Path $script:StateFile -Encoding UTF8

    if (-not (Test-Path $script:RegPath)) { New-Item -Path $script:RegPath -Force | Out-Null }
    Set-ItemProperty -Path $script:RegPath -Name 'ProxyServer'   -Value $Server -Type String
    Set-ItemProperty -Path $script:RegPath -Name 'ProxyOverride' -Value $Bypass -Type String
    Set-ItemProperty -Path $script:RegPath -Name 'ProxyEnable'   -Value 1 -Type DWord
    Update-WinInetSettings
    Write-Host "  [+] HKCU proxy set to $Server (bypass: $Bypass)" -ForegroundColor Green
}

function Unregister-UserProxy {
    <# Roll HKCU back to whatever was there before we started. #>
    if (-not $script:OnWindows) { return }
    if (-not (Test-Path $script:StateFile)) {
        Write-Host '  [i] No checkpoint file found; leaving proxy settings alone.' -ForegroundColor DarkGray
        return
    }
    try {
        $cp = Get-Content -Path $script:StateFile -Raw | ConvertFrom-Json

        if ($null -ne $cp.ProxyEnable) { Set-ItemProperty -Path $script:RegPath -Name 'ProxyEnable' -Value ([int]$cp.ProxyEnable) -Type DWord }
        else { Remove-ItemProperty -Path $script:RegPath -Name 'ProxyEnable' -ErrorAction SilentlyContinue }

        if ($null -ne $cp.ProxyServer) { Set-ItemProperty -Path $script:RegPath -Name 'ProxyServer' -Value ([string]$cp.ProxyServer) -Type String }
        else { Remove-ItemProperty -Path $script:RegPath -Name 'ProxyServer' -ErrorAction SilentlyContinue }

        if ($null -ne $cp.ProxyOverride) { Set-ItemProperty -Path $script:RegPath -Name 'ProxyOverride' -Value ([string]$cp.ProxyOverride) -Type String }
        else { Remove-ItemProperty -Path $script:RegPath -Name 'ProxyOverride' -ErrorAction SilentlyContinue }

        Update-WinInetSettings
        Remove-Item -Path $script:StateFile -Force -ErrorAction SilentlyContinue
        Write-Host '  [+] Proxy settings restored from checkpoint.' -ForegroundColor Green
    }
    catch {
        Write-Warning "Restore failed: $($_.Exception.Message)"
        Write-Warning "Fix manually under: $script:RegPath"
    }
}
#endregion

#region ------------------------------------------------------------ proxy worker
$ProxyWorker = {
    param($Client, $Ctx)

    $clientStream = $null
    $remote = $null
    $peer = '?'
    try {
        $peer = $Client.Client.RemoteEndPoint.ToString()
        $Client.NoDelay = $true
        $Client.ReceiveTimeout = 20000
        $Client.SendTimeout = 20000
        $clientStream = $Client.GetStream()

        # --- read the request head without swallowing any of the body -------------
        $buf = New-Object byte[] 8192
        $acc = New-Object System.IO.MemoryStream
        $headEnd = -1
        while ($headEnd -lt 0 -and $acc.Length -lt 65536) {
            $n = $clientStream.Read($buf, 0, $buf.Length)
            if ($n -le 0) { break }
            $acc.Write($buf, 0, $n)
            $snapshot = $acc.ToArray()
            $headEnd = Find-HeaderEnd -Buffer $snapshot -Length $snapshot.Length
        }
        $raw = $acc.ToArray()
        if ($headEnd -lt 0) { return }

        $headText = [Text.Encoding]::ASCII.GetString($raw, 0, $headEnd)
        # Anything the client pipelined after the head has to be forwarded verbatim.
        $leftover = New-Object byte[] ($raw.Length - $headEnd)
        if ($leftover.Length -gt 0) { [Array]::Copy($raw, $headEnd, $leftover, 0, $leftover.Length) }

        $lines = $headText -split "`r?`n"
        $requestLine = $lines[0]
        $parts = $requestLine -split '\s+'
        if ($parts.Count -lt 3) { return }
        $method = $parts[0].ToUpperInvariant()
        $target = $parts[1]
        $version = $parts[2]

        # --- work out where the client actually wants to go ----------------------
        $destHost = $null; $destPort = 0; $originPath = $null
        if ($method -eq 'CONNECT') {
            # CONNECT host:port HTTP/1.1
            if ($target -match '^\[(?<h>[^\]]+)\](?::(?<p>\d+))?$') {
                $destHost = $Matches['h']
                $destPort = if ($Matches['p']) { [int]$Matches['p'] } else { 443 }
            }
            elseif ($target -match '^(?<h>[^:]+):(?<p>\d+)$') {
                $destHost = $Matches['h']; $destPort = [int]$Matches['p']
            }
            else { $destHost = $target; $destPort = 443 }
        }
        elseif ($target -match '^[a-zA-Z][a-zA-Z0-9+.\-]*://') {
            # absolute-form: the shape a client uses when it knows it is talking to a proxy
            try {
                $uri = [Uri]$target
                $destHost = $uri.Host
                $destPort = if ($uri.IsDefaultPort) { if ($uri.Scheme -eq 'https') { 443 } else { 80 } } else { $uri.Port }
                $originPath = $uri.PathAndQuery
                if (-not $originPath) { $originPath = '/' }
            }
            catch { return }
        }
        else {
            # origin-form: someone pointed an app straight at us as though we were the
            # server. Fall back to the Host header so we still do something useful.
            $hostHeader = ($lines | Where-Object { $_ -match '^\s*Host\s*:' } | Select-Object -First 1)
            if (-not $hostHeader) {
                $msg = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 400 Bad Request`r`nConnection: close`r`n`r`n")
                $clientStream.Write($msg, 0, $msg.Length)
                return
            }
            $hv = ($hostHeader -split ':', 2)[1].Trim()
            if ($hv -match '^(?<h>[^:]+):(?<p>\d+)$') { $destHost = $Matches['h']; $destPort = [int]$Matches['p'] }
            else { $destHost = $hv; $destPort = 80 }
            $originPath = $target
        }

        if (-not $destHost) { return }
        $destHost = $destHost.TrimEnd('.')

        # --- rule engine ---------------------------------------------------------
        $dest = Resolve-Destination -TargetHost $destHost -TargetPort $destPort -Ctx $Ctx

        if ($dest.Redirected) {
            Add-Counter -Ctx $Ctx -Name 'Redirected'
            Write-Log -Ctx $Ctx -Level 'REDIR' -Message ("{0} {1}:{2} -> {3}:{4}  [{5}]" -f $method, $destHost, $destPort, $dest.Host, $dest.Port, $dest.Rule)
        }
        else {
            Add-Counter -Ctx $Ctx -Name 'Passed'
            if ($Ctx.LogTraffic) {
                Write-Log -Ctx $Ctx -Level 'PASS ' -Message ("{0} {1}:{2}" -f $method, $destHost, $destPort)
            }
        }

        # --- dial the destination ------------------------------------------------
        $remote = New-Object System.Net.Sockets.TcpClient
        $remote.NoDelay = $true
        try {
            $connect = $remote.ConnectAsync($dest.Host, $dest.Port)
            if (-not $connect.Wait(10000)) { throw 'connect timed out' }
            if ($connect.IsFaulted) { throw $connect.Exception.GetBaseException().Message }
        }
        catch {
            Write-Log -Ctx $Ctx -Level 'FAIL ' -Message ("{0}:{1} unreachable - {2}" -f $dest.Host, $dest.Port, $_.Exception.Message)
            $body = "Loopback redirector: nothing is listening on $($dest.Host):$($dest.Port)."
            $resp = "HTTP/1.1 502 Bad Gateway`r`nContent-Type: text/plain`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n$body"
            $bytes = [Text.Encoding]::ASCII.GetBytes($resp)
            try { $clientStream.Write($bytes, 0, $bytes.Length) } catch { }
            return
        }

        $remote.ReceiveTimeout = 0
        $remote.SendTimeout = 0
        $Client.ReceiveTimeout = 0
        $Client.SendTimeout = 0
        $remoteStream = $remote.GetStream()

        if ($method -eq 'CONNECT') {
            # Signal success, then get out of the way. We never decrypt: the TLS
            # session is negotiated end to end between the client and whatever is
            # listening on the loopback port.
            $ok = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 Connection Established`r`nProxy-Agent: LoopbackRedirect`r`n`r`n")
            $clientStream.Write($ok, 0, $ok.Length)
            $clientStream.Flush()
            if ($leftover.Length -gt 0) { $remoteStream.Write($leftover, 0, $leftover.Length) }
        }
        else {
            # Rewrite absolute-form to origin-form: we are handing this to an origin
            # server, not to another proxy, so the absolute URI would be rejected.
            $rebuilt = New-Object System.Text.StringBuilder
            [void]$rebuilt.Append("$method $originPath $version`r`n")
            $headerLines = if ($lines.Count -gt 1) { $lines[1..($lines.Count - 1)] } else { @() }
            foreach ($line in $headerLines) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                $name = ($line -split ':', 2)[0].Trim().ToLowerInvariant()
                # Hop-by-hop headers must not be forwarded.
                if ($name -in @('proxy-connection', 'proxy-authorization', 'connection', 'keep-alive', 'te', 'trailer', 'upgrade')) { continue }
                [void]$rebuilt.Append("$line`r`n")
            }
            # One request per connection keeps a rewritten keep-alive stream from
            # sending a later request for a different host down this same socket.
            [void]$rebuilt.Append("Connection: close`r`n`r`n")

            $headBytes = [Text.Encoding]::ASCII.GetBytes($rebuilt.ToString())
            $remoteStream.Write($headBytes, 0, $headBytes.Length)
            if ($leftover.Length -gt 0) { $remoteStream.Write($leftover, 0, $leftover.Length) }
            $remoteStream.Flush()
        }

        Copy-Duplex -StreamA $clientStream -StreamB $remoteStream
    }
    catch {
        try { Write-Log -Ctx $Ctx -Level 'ERR  ' -Message ("{0} - {1}" -f $peer, $_.Exception.Message) } catch { }
    }
    finally {
        if ($remote) { try { $remote.Close() } catch { } }
        if ($Client) { try { $Client.Close() } catch { } }
    }
}
#endregion

#region ------------------------------------------------------------- sink worker
$SinkWorker = {
    param($Client, $Ctx, $LocalPort)
    try {
        $Client.ReceiveTimeout = 5000
        $s = $Client.GetStream()
        $buf = New-Object byte[] 4096
        $n = 0
        try { $n = $s.Read($buf, 0, $buf.Length) } catch { }
        $first = if ($n -gt 0) { ([Text.Encoding]::ASCII.GetString($buf, 0, $n) -split "`r?`n")[0] } else { '(no data)' }

        # A TLS ClientHello starts with 0x16 0x03 - it is not HTTP, so replying with
        # an HTTP error would only produce a confusing parse failure at the client.
        if ($n -ge 2 -and $buf[0] -eq 0x16 -and $buf[1] -eq 0x03) {
            Write-Log -Ctx $Ctx -Level 'SINK ' -Message "port $LocalPort received a TLS handshake - closing (no certificate configured)"
            return
        }

        Write-Log -Ctx $Ctx -Level 'SINK ' -Message ("port {0} <- {1}" -f $LocalPort, $first)
        $safe = $first.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;')
        $body = @"
<!doctype html><html><head><meta charset="utf-8"><title>Redirected</title>
<style>body{font:16px/1.6 system-ui,sans-serif;margin:15vh auto;max-width:34rem;color:#222}
code{background:#f2f2f2;padding:.15em .4em;border-radius:3px}</style></head>
<body><h1>Redirected to 127.0.0.1</h1>
<p>This request matched a redirect rule and was sent to the loopback sink on port <code>$LocalPort</code> instead of its real destination.</p>
<p>Original request line: <code>$safe</code></p></body></html>
"@
        $bodyBytes = [Text.Encoding]::UTF8.GetBytes($body)
        $head = "HTTP/1.1 200 OK`r`nContent-Type: text/html; charset=utf-8`r`nContent-Length: $($bodyBytes.Length)`r`nConnection: close`r`n`r`n"
        $headBytes = [Text.Encoding]::ASCII.GetBytes($head)
        $s.Write($headBytes, 0, $headBytes.Length)
        $s.Write($bodyBytes, 0, $bodyBytes.Length)
        $s.Flush()
    }
    catch { }
    finally { try { $Client.Close() } catch { } }
}
#endregion

#region -------------------------------------------------------------- DNS server
$DnsWorker = {
    param($Ctx)

    # DNS wire format, built by hand. Header is 12 bytes:
    #   0-1 ID | 2-3 flags | 4-5 QDCOUNT | 6-7 ANCOUNT | 8-9 NSCOUNT | 10-11 ARCOUNT
    # The question section follows as length-prefixed labels terminated by 0x00,
    # then QTYPE and QCLASS as 16-bit big-endian values.
    $udp = $null
    try {
        $bindEp = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Loopback), $Ctx.DnsPort
        $udp = New-Object System.Net.Sockets.UdpClient $bindEp
        $udp.Client.ReceiveTimeout = 500
        Write-Log -Ctx $Ctx -Level 'DNS  ' -Message "listening on 127.0.0.1:$($Ctx.DnsPort), upstream $($Ctx.UpstreamDns)"

        while ($Ctx.Running) {
            $remoteEp = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any), 0
            $data = $null
            try { $data = $udp.Receive([ref]$remoteEp) }
            catch [System.Net.Sockets.SocketException] { continue }   # 500 ms poll tick
            if (-not $data -or $data.Length -lt 13) { continue }

            # --- decode QNAME -------------------------------------------------
            $i = 12
            $labels = New-Object System.Collections.Generic.List[string]
            $bad = $false
            while ($true) {
                if ($i -ge $data.Length) { $bad = $true; break }
                $len = [int]$data[$i]
                if ($len -eq 0) { $i++; break }
                if (($len -band 0xC0) -ne 0) { $bad = $true; break }   # pointer in a question: malformed
                if ($i + 1 + $len -gt $data.Length) { $bad = $true; break }
                $labels.Add([Text.Encoding]::ASCII.GetString($data, $i + 1, $len))
                $i += 1 + $len
            }
            if ($bad -or ($i + 3) -ge $data.Length) { continue }

            $qname = ($labels -join '.')
            $qtype = ([int]$data[$i] -shl 8) -bor [int]$data[$i + 1]
            $questionEnd = $i + 4        # QTYPE(2) + QCLASS(2)

            $dest = Resolve-Destination -TargetHost $qname -TargetPort 53 -Ctx $Ctx
            $isLoopbackTarget = $dest.Redirected -and ($dest.Host -eq '127.0.0.1' -or $dest.Host -eq '::1')

            if ($isLoopbackTarget -and ($qtype -eq 1 -or $qtype -eq 28)) {
                # --- synthesise an answer -------------------------------------
                $resp = New-Object System.Collections.Generic.List[byte]
                for ($k = 0; $k -lt $questionEnd; $k++) { $resp.Add($data[$k]) }

                # QR=1, keep opcode/RD, set AA
                $resp[2] = [byte]((([int]$data[2] -band 0x7F) -bor 0x80) -bor 0x04)
                $resp[3] = [byte]0x80          # RA=1, RCODE=NOERROR
                $resp[6] = [byte]0; $resp[7] = [byte]1     # ANCOUNT = 1
                $resp[8] = [byte]0; $resp[9] = [byte]0     # NSCOUNT = 0
                $resp[10] = [byte]0; $resp[11] = [byte]0   # ARCOUNT = 0

                # 0xC00C is a compression pointer back to the QNAME at offset 12.
                $resp.AddRange([byte[]]@(0xC0, 0x0C))
                if ($qtype -eq 1) {
                    $resp.AddRange([byte[]]@(0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1E, 0x00, 0x04))
                    $resp.AddRange([byte[]]@(127, 0, 0, 1))
                }
                else {
                    $resp.AddRange([byte[]]@(0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1E, 0x00, 0x10))
                    $v6 = New-Object byte[] 16
                    $v6[15] = 1                                    # ::1
                    $resp.AddRange($v6)
                }

                $out = $resp.ToArray()
                [void]$udp.Send($out, $out.Length, $remoteEp)
                Add-Counter -Ctx $Ctx -Name 'DnsRedirected'
                $rtype = if ($qtype -eq 1) { 'A 127.0.0.1' } else { 'AAAA ::1' }
                Write-Log -Ctx $Ctx -Level 'DNS  ' -Message ("{0} -> {1}  [{2}]" -f $qname, $rtype, $dest.Rule)
                continue
            }

            # --- relay everything else upstream --------------------------------
            $fwd = $null
            try {
                $fwd = New-Object System.Net.Sockets.UdpClient
                $fwd.Client.ReceiveTimeout = 3000
                $fwd.Connect($Ctx.UpstreamDns, 53)
                [void]$fwd.Send($data, $data.Length)
                $anyEp = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any), 0
                $reply = $fwd.Receive([ref]$anyEp)
                [void]$udp.Send($reply, $reply.Length, $remoteEp)
                Add-Counter -Ctx $Ctx -Name 'DnsForwarded'
                if ($Ctx.LogTraffic) { Write-Log -Ctx $Ctx -Level 'DNS  ' -Message "$qname -> upstream" }
            }
            catch {
                # SERVFAIL so the client fails fast instead of waiting out its timeout
                if ($data.Length -ge 12) {
                    $sf = $data.Clone()
                    $sf[2] = [byte]((([int]$data[2] -band 0x7F) -bor 0x80))
                    $sf[3] = [byte]0x82
                    [void]$udp.Send($sf, $sf.Length, $remoteEp)
                }
            }
            finally { if ($fwd) { try { $fwd.Close() } catch { } } }
        }
    }
    catch { try { Write-Log -Ctx $Ctx -Level 'DNS  ' -Message "server stopped: $($_.Exception.Message)" } catch { } }
    finally { if ($udp) { try { $udp.Close() } catch { } } }
}
#endregion

#region ---------------------------------------------------------------- selftest
function Invoke-SelfTest {
    $script:pass = 0
    $script:fail = 0
    function Assert-Match {
        param([string] $RuleText, [string] $TestHost, [int] $Port, [bool] $Expected, [string] $Because)
        $r = New-RedirectRule -Line $RuleText
        $got = [bool](Test-RuleMatch -Rule $r -TargetHost $TestHost -TargetPort $Port)
        if ($got -eq $Expected) {
            $script:pass++
            Write-Host ("  PASS  {0,-28} {1,-26} => {2}" -f $RuleText, "$TestHost`:$Port", $got) -ForegroundColor DarkGreen
        }
        else {
            $script:fail++
            Write-Host ("  FAIL  {0,-28} {1,-26} => {2} (expected {3}) - {4}" -f $RuleText, "$TestHost`:$Port", $got, $Expected, $Because) -ForegroundColor Red
        }
    }

    Write-Host "`n  Rule engine self-test" -ForegroundColor Cyan
    Write-Host '  ---------------------' -ForegroundColor DarkGray

    Assert-Match 'example.com'        'example.com'      80  $true  'exact host'
    Assert-Match 'example.com'        'EXAMPLE.COM'      80  $true  'case insensitive'
    Assert-Match 'example.com'        'example.com.'     80  $true  'trailing root dot'
    Assert-Match 'example.com'        'notexample.com'   80  $false 'no substring matching'
    Assert-Match 'example.com'        'www.example.com'  80  $false 'exact rule is not a suffix rule'

    Assert-Match '*.tracker.net'      'ads.tracker.net'  80  $true  'wildcard label'
    Assert-Match '*.tracker.net'      'a.b.tracker.net'  80  $true  'wildcard spans labels'
    Assert-Match '*.tracker.net'      'tracker.net'      80  $true  'wildcard also matches apex'
    Assert-Match '*.tracker.net'      'tracker.net.evil.com' 80 $false 'suffix must be terminal'

    Assert-Match 'api.example.com:443' 'api.example.com' 443 $true  'port qualifier matches'
    Assert-Match 'api.example.com:443' 'api.example.com' 80  $false 'port qualifier excludes'

    Assert-Match '93.184.216.34'      '93.184.216.34'    80  $true  'ipv4 literal'
    Assert-Match '93.184.216.34'      '93.184.216.35'    80  $false 'neighbouring ip'

    Assert-Match '10.20.0.0/16'       '10.20.255.254'    80  $true  'inside cidr'
    Assert-Match '10.20.0.0/16'       '10.21.0.1'        80  $false 'outside cidr'
    Assert-Match '10.0.0.0/8'         '10.255.255.255'   80  $true  'wide cidr'
    Assert-Match '192.168.1.100/32'   '192.168.1.100'    80  $true  '/32 host route'
    Assert-Match '192.168.1.100/32'   '192.168.1.101'    80  $false '/32 excludes neighbour'
    Assert-Match '0.0.0.0/0'          '8.8.8.8'          80  $true  '/0 matches everything'
    Assert-Match '10.20.0.0/16'       'example.com'      80  $false 'cidr never matches a name'
    Assert-Match '203.0.113.0/24'     '203.0.113.7'      80  $true  'documentation range'
    Assert-Match '203.0.113.0/24'     '203.0.114.7'      80  $false 'adjacent /24'

    Write-Host "`n  Target parsing" -ForegroundColor Cyan
    Write-Host '  --------------' -ForegroundColor DarkGray
    $ctx = @{ Rules = @(); CatchAll = $false }
    $cases = @(
        @{ Rule = 'a.com'; Host = 'a.com'; Port = 80; Expect = '127.0.0.1:80' }
        @{ Rule = 'b.com => 9000'; Host = 'b.com'; Port = 80; Expect = '127.0.0.1:9000' }
        @{ Rule = 'c.com => :8443'; Host = 'c.com'; Port = 443; Expect = '127.0.0.1:8443' }
        @{ Rule = 'd.com => 127.0.0.1:3000'; Host = 'd.com'; Port = 443; Expect = '127.0.0.1:3000' }
        @{ Rule = 'e.com -> 5000'; Host = 'e.com'; Port = 80; Expect = '127.0.0.1:5000' }
        @{ Rule = 'f.com = 6000'; Host = 'f.com'; Port = 80; Expect = '127.0.0.1:6000' }
    )
    foreach ($c in $cases) {
        $ctx.Rules = @(New-RedirectRule -Line $c.Rule)
        $d = Resolve-Destination -TargetHost $c.Host -TargetPort $c.Port -Ctx $ctx
        $got = "$($d.Host):$($d.Port)"
        if ($got -eq $c.Expect) {
            $script:pass++
            Write-Host ("  PASS  {0,-28} => {1}" -f $c.Rule, $got) -ForegroundColor DarkGreen
        }
        else {
            $script:fail++
            Write-Host ("  FAIL  {0,-28} => {1} (expected {2})" -f $c.Rule, $got, $c.Expect) -ForegroundColor Red
        }
    }

    Write-Host "`n  Precedence and pass-through" -ForegroundColor Cyan
    Write-Host '  ---------------------------' -ForegroundColor DarkGray
    $ctx.Rules = @(
        (New-RedirectRule -Line 'api.example.com => 127.0.0.1:9000'),
        (New-RedirectRule -Line '*.example.com')
    )
    $ctx.CatchAll = $false
    $checks = @(
        @{ Host = 'api.example.com'; Port = 443; Host2 = '127.0.0.1'; Port2 = 9000; Redir = $true; Why = 'first rule wins' }
        @{ Host = 'cdn.example.com'; Port = 443; Host2 = '127.0.0.1'; Port2 = 443; Redir = $true; Why = 'second rule, port preserved' }
        @{ Host = 'other.org'; Port = 443; Host2 = 'other.org'; Port2 = 443; Redir = $false; Why = 'unmatched passes through' }
    )
    foreach ($c in $checks) {
        $d = Resolve-Destination -TargetHost $c.Host -TargetPort $c.Port -Ctx $ctx
        if ($d.Host -eq $c.Host2 -and $d.Port -eq $c.Port2 -and $d.Redirected -eq $c.Redir) {
            $script:pass++
            Write-Host ("  PASS  {0,-22} => {1}:{2} redirected={3}" -f $c.Host, $d.Host, $d.Port, $d.Redirected) -ForegroundColor DarkGreen
        }
        else {
            $script:fail++
            Write-Host ("  FAIL  {0,-22} => {1}:{2} redirected={3} - {4}" -f $c.Host, $d.Host, $d.Port, $d.Redirected, $c.Why) -ForegroundColor Red
        }
    }

    $ctx.CatchAll = $true
    $d = Resolve-Destination -TargetHost 'anything.at.all' -TargetPort 8080 -Ctx $ctx
    if ($d.Redirected -and $d.Host -eq '127.0.0.1' -and $d.Port -eq 8080) {
        $script:pass++; Write-Host '  PASS  catch-all captures unmatched hosts on their original port' -ForegroundColor DarkGreen
    }
    else { $script:fail++; Write-Host '  FAIL  catch-all' -ForegroundColor Red }

    Write-Host "`n  Comment and blank handling" -ForegroundColor Cyan
    Write-Host '  --------------------------' -ForegroundColor DarkGray
    $inline = New-RedirectRule -Line 'a.com => 127.0.0.1:9000   # trailing note'
    if ($inline.TargetHost -eq '127.0.0.1' -and $inline.TargetPort -eq 9000) {
        $script:pass++; Write-Host '  PASS  inline trailing comment stripped from target' -ForegroundColor DarkGreen
    }
    else { $script:fail++; Write-Host ("  FAIL  inline comment: got {0}:{1}" -f $inline.TargetHost, $inline.TargetPort) -ForegroundColor Red }

    foreach ($junk in @('', '   ', '# comment', '; comment')) {
        if ($null -eq (New-RedirectRule -Line $junk)) {
            $script:pass++; Write-Host ("  PASS  ignored: '{0}'" -f $junk) -ForegroundColor DarkGreen
        }
        else { $script:fail++; Write-Host ("  FAIL  should ignore: '{0}'" -f $junk) -ForegroundColor Red }
    }

    Write-Host ''
    $color = if ($script:fail -eq 0) { 'Green' } else { 'Red' }
    Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $color
    Write-Host ''
    return ($script:fail -eq 0)
}
#endregion

#region -------------------------------------------------------------- entrypoint
function Show-Banner {
    Write-Host ''
    Write-Host '  loopback redirector' -ForegroundColor Cyan
    Write-Host '  userland traffic redirection to 127.0.0.1 - no elevation required' -ForegroundColor DarkGray
    Write-Host ''
}

switch ($Mode) {

    'SelfTest' {
        Show-Banner
        $ok = Invoke-SelfTest
        exit $(if ($ok) { 0 } else { 1 })
    }

    'Stop' {
        Show-Banner
        Unregister-UserProxy
        exit 0
    }

    'Status' {
        Show-Banner
        if ($script:OnWindows) {
            Write-Host '  HKCU Internet Settings' -ForegroundColor Cyan
            foreach ($n in 'ProxyEnable', 'ProxyServer', 'ProxyOverride') {
                $v = Get-RegValueOrNull $n
                Write-Host ("    {0,-14} {1}" -f $n, $(if ($null -ne $v) { $v } else { '(not set)' }))
            }
            Write-Host ''
            Write-Host ("  Checkpoint file: {0}" -f $(if (Test-Path $script:StateFile) { $script:StateFile } else { '(none)' }))
        }
        else { Write-Host '  Not on Windows - no registry state to report.' -ForegroundColor Yellow }

        Write-Host ''
        Write-Host '  Loopback listeners' -ForegroundColor Cyan
        $probe = @($ProxyPort) + $SinkPorts | Select-Object -Unique
        foreach ($p in $probe) {
            $t = New-Object System.Net.Sockets.TcpClient
            try {
                $ok = $t.ConnectAsync('127.0.0.1', $p).Wait(300)
                Write-Host ("    tcp/{0,-6} {1}" -f $p, $(if ($ok) { 'listening' } else { 'closed' }))
            }
            catch { Write-Host ("    tcp/{0,-6} closed" -f $p) }
            finally { $t.Close() }
        }
        Write-Host ''
        exit 0
    }

    'Run' {
        Show-Banner

        # ---------------------------------------------------------- build rules
        $ruleLines = New-Object System.Collections.Generic.List[string]
        foreach ($r in $Redirect) { if ($r) { $ruleLines.Add($r) } }
        if ($RuleFile) {
            if (-not (Test-Path $RuleFile)) { throw "Rule file not found: $RuleFile" }
            foreach ($l in Get-Content -Path $RuleFile) { $ruleLines.Add($l) }
        }

        $rules = New-Object System.Collections.Generic.List[object]
        foreach ($l in $ruleLines) {
            $rule = New-RedirectRule -Line $l
            if ($rule) { $rules.Add($rule) }
        }

        if ($rules.Count -eq 0 -and -not $CatchAll) {
            Write-Warning 'No rules and no -CatchAll: every connection would simply pass through.'
            Write-Warning "Try: -Redirect 'example.com','*.tracker.net'   or   -CatchAll"
            Write-Host ''
        }

        Write-Host '  Rules' -ForegroundColor Cyan
        if ($rules.Count -eq 0) { Write-Host '    (none)' -ForegroundColor DarkGray }
        foreach ($r in $rules) {
            $tgt = "$(if ($r.TargetHost) { $r.TargetHost } else { '127.0.0.1' }):$(if ($r.TargetPort -gt 0) { $r.TargetPort } else { '<same>' })"
            Write-Host ("    {0,-9} {1,-32} -> {2}" -f $r.Kind, $r.Pattern, $tgt) -ForegroundColor Gray
        }
        if ($CatchAll) { Write-Host '    CATCHALL  <everything else>              -> 127.0.0.1:<same>' -ForegroundColor Yellow }
        Write-Host ''

        # -------------------------------------------------------- shared context
        $Ctx = [hashtable]::Synchronized(@{
                Rules       = $rules.ToArray()
                CatchAll    = [bool]$CatchAll
                LogTraffic  = [bool]$LogTraffic
                Running     = $true
                DnsPort     = $DnsPort
                UpstreamDns = $UpstreamDns
                Log         = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
                Counters    = [hashtable]::Synchronized(@{
                        Redirected = 0; Passed = 0; DnsRedirected = 0; DnsForwarded = 0
                    })
            })

        # ------------------------------------------------------- runspace pool
        # Worker runspaces do not inherit the caller's functions, so the rule engine
        # is injected into the InitialSessionState and $Ctx is bound as a shared
        # variable - every thread then reads the same live rule set.
        $shared = 'ConvertTo-IPv4UInt32', 'Test-RuleMatch', 'Resolve-Destination', 'Write-Log', 'Add-Counter', 'Find-HeaderEnd', 'Copy-Duplex'
        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        foreach ($fn in $shared) {
            $def = (Get-Command -Name $fn -CommandType Function).Definition
            $iss.Commands.Add(
                [System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($fn, $def))
        }
        $pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $iss, $Host)
        try { $pool.ApartmentState = 'MTA' } catch { }   # not supported off-Windows
        $pool.Open()

        $jobs = New-Object System.Collections.Generic.List[object]
        $listeners = New-Object System.Collections.Generic.List[object]
        $proxyListener = $null
        $dnsPs = $null
        $proxyRegistered = $false

        function Start-LoopbackListener {
            param([int] $Port, [string] $Label)
            $l = New-Object System.Net.Sockets.TcpListener ([System.Net.IPAddress]::Loopback), $Port
            try {
                # Binding low ports needs no elevation on Windows; only the http.sys
                # based HttpListener would have demanded an admin URL reservation.
                $l.Start(200)
                Write-Host ("  [+] {0} on 127.0.0.1:{1}" -f $Label, $Port) -ForegroundColor Green
                return $l
            }
            catch {
                Write-Host ("  [!] cannot bind 127.0.0.1:{0} - {1}" -f $Port, $_.Exception.Message) -ForegroundColor Red
                Write-Host '      (port in use, or inside a Hyper-V/WSL reserved range - see `netsh int ipv4 show excludedportrange protocol=tcp`)' -ForegroundColor DarkGray
                return $null
            }
        }

        try {
            Write-Host '  Listeners' -ForegroundColor Cyan
            $proxyListener = Start-LoopbackListener -Port $ProxyPort -Label 'proxy    '
            if (-not $proxyListener) { throw "Could not bind the proxy port $ProxyPort." }

            $sinkListeners = @{}
            if ($Sink) {
                foreach ($sp in ($SinkPorts | Select-Object -Unique)) {
                    if ($sp -eq $ProxyPort) { continue }
                    $sl = Start-LoopbackListener -Port $sp -Label 'sink     '
                    if ($sl) { $sinkListeners[$sp] = $sl; $listeners.Add($sl) }
                }
            }

            if ($EnableDnsServer) {
                $dnsPs = [powershell]::Create()
                $dnsPs.RunspacePool = $pool
                [void]$dnsPs.AddScript($DnsWorker).AddArgument($Ctx)
                $dnsHandle = $dnsPs.BeginInvoke()
                Write-Host ("  [+] dns      on 127.0.0.1:{0} (udp)" -f $DnsPort) -ForegroundColor Green
            }
            Write-Host ''

            if (-not $NoSystemProxy) {
                Write-Host '  System integration' -ForegroundColor Cyan
                Register-UserProxy -Server "127.0.0.1:$ProxyPort" -Bypass $ProxyBypass
                $proxyRegistered = $true
                Write-Host ''
            }
            else {
                Write-Host "  [i] -NoSystemProxy: configure clients manually, e.g." -ForegroundColor DarkGray
                Write-Host "      curl -x http://127.0.0.1:$ProxyPort https://example.com" -ForegroundColor DarkGray
                Write-Host ''
            }

            Write-Host '  Running. Press Q or Ctrl+C to stop and restore settings.' -ForegroundColor Cyan
            Write-Host ''

            $interactive = $true
            try { $null = [Console]::KeyAvailable } catch { $interactive = $false }
            $deadline = if ($RunSeconds -gt 0) { (Get-Date).AddSeconds($RunSeconds) } else { [datetime]::MaxValue }

            while ($Ctx.Running) {

                # ---- accept proxy connections
                while ($proxyListener.Pending()) {
                    $client = $proxyListener.AcceptTcpClient()
                    $ps = [powershell]::Create()
                    $ps.RunspacePool = $pool
                    [void]$ps.AddScript($ProxyWorker).AddArgument($client).AddArgument($Ctx)
                    $jobs.Add([pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke() })
                }

                # ---- accept sink connections
                foreach ($kv in @($sinkListeners.GetEnumerator())) {
                    while ($kv.Value.Pending()) {
                        $client = $kv.Value.AcceptTcpClient()
                        $ps = [powershell]::Create()
                        $ps.RunspacePool = $pool
                        [void]$ps.AddScript($SinkWorker).AddArgument($client).AddArgument($Ctx).AddArgument($kv.Key)
                        $jobs.Add([pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke() })
                    }
                }

                # ---- reap finished workers
                for ($j = $jobs.Count - 1; $j -ge 0; $j--) {
                    if ($jobs[$j].Handle.IsCompleted) {
                        try { [void]$jobs[$j].PS.EndInvoke($jobs[$j].Handle) } catch { }
                        $jobs[$j].PS.Dispose()
                        $jobs.RemoveAt($j)
                    }
                }

                # ---- drain the log queue on the console thread
                $line = ''
                while ($Ctx.Log.TryDequeue([ref]$line)) {
                    $bits = $line -split '\|', 3
                    $color = switch ($bits[1].Trim()) {
                        'REDIR' { 'Yellow' }
                        'SINK' { 'Magenta' }
                        'DNS' { 'Cyan' }
                        'FAIL' { 'Red' }
                        'ERR' { 'DarkRed' }
                        default { 'DarkGray' }
                    }
                    Write-Host ("  {0} {1} {2}" -f $bits[0], $bits[1], $bits[2]) -ForegroundColor $color
                }

                # ---- quit conditions
                if ($interactive -and [Console]::KeyAvailable) {
                    $k = [Console]::ReadKey($true)
                    if ($k.Key -eq 'Q' -or ($k.Key -eq 'C' -and $k.Modifiers -band [ConsoleModifiers]::Control)) {
                        $Ctx.Running = $false
                    }
                }
                if ((Get-Date) -gt $deadline) { $Ctx.Running = $false }

                Start-Sleep -Milliseconds 30
            }
        }
        finally {
            # This block is the whole reason the script is safe to Ctrl+C: the HKCU
            # values are put back before the process exits.
            $Ctx.Running = $false
            Write-Host ''
            Write-Host '  Shutting down' -ForegroundColor Cyan

            if ($proxyRegistered) { Unregister-UserProxy }

            if ($proxyListener) { try { $proxyListener.Stop() } catch { } }
            foreach ($l in $listeners) { try { $l.Stop() } catch { } }

            $spin = 0
            while ($jobs.Count -gt 0 -and $spin -lt 60) {
                for ($j = $jobs.Count - 1; $j -ge 0; $j--) {
                    if ($jobs[$j].Handle.IsCompleted) {
                        try { [void]$jobs[$j].PS.EndInvoke($jobs[$j].Handle) } catch { }
                        $jobs[$j].PS.Dispose(); $jobs.RemoveAt($j)
                    }
                }
                Start-Sleep -Milliseconds 100; $spin++
            }
            foreach ($j in $jobs) { try { $j.PS.Stop(); $j.PS.Dispose() } catch { } }
            if ($dnsPs) { try { $dnsPs.Stop(); $dnsPs.Dispose() } catch { } }
            if ($pool) { try { $pool.Close(); $pool.Dispose() } catch { } }

            Write-Host ''
            Write-Host '  Totals' -ForegroundColor Cyan
            Write-Host ("    tcp redirected  {0}" -f $Ctx.Counters.Redirected)
            Write-Host ("    tcp passed      {0}" -f $Ctx.Counters.Passed)
            if ($EnableDnsServer) {
                Write-Host ("    dns redirected  {0}" -f $Ctx.Counters.DnsRedirected)
                Write-Host ("    dns forwarded   {0}" -f $Ctx.Counters.DnsForwarded)
            }
            Write-Host ''
        }
    }
}
#endregion
