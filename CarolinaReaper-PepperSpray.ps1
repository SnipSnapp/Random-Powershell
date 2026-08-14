#Requires -Version 5.1
<#
    Invoke-LoopbackRedirect.ps1

    Sends selected hostnames / IP ranges to 127.0.0.1 without needing admin.

    The obvious ways to do this all want elevation - hosts file (ACL), route add,
    netsh, WFP, Set-DnsClientServerAddress, NRPT. So instead: run a small proxy on
    loopback and point HKCU's ProxyServer at it. Anything matching a rule gets
    dialled to 127.0.0.1, everything else is tunnelled straight through.

    TcpListener, not HttpListener - the latter goes through http.sys and needs an
    admin-registered URL ACL. Raw sockets don't, and Windows doesn't reserve ports
    under 1024 the way Unix does, so we can take :80 and :53 as a normal user.

    Optionally serves DNS on 127.0.0.1:53 for clients that let you point them at a
    resolver. Matches get A 127.0.0.1 / AAAA ::1, everything else is relayed.

    Static ProxyServer only - no PAC, no WPAD. See Set-ProxyRegValue.

    Four interception paths, because no single one catches everything:
      http proxy  :8080  http + CONNECT, what browsers and .NET use
      socks proxy :1080  socks5/4a, any tcp protocol not just http
      env vars           http_proxy/all_proxy for curl, python, node, go, java
      dns         :53    for clients you can point at a resolver

    WHAT THIS DOES NOT COVER. This is one user's traffic, from applications that
    consult a proxy setting. It is not machine wide and it is not enforced:
      - only the user running it. other accounts and SYSTEM services have their
        own registry hive and are untouched.
      - only apps that opt in. anything opening a raw socket and ignoring proxy
        config goes straight out and never sees us.
      - env vars only reach processes started after they are set. use -Launch to
        inject them into one immediately.
      - non tcp is out of reach. udp, quic/http3, icmp.
      - uwp/store apps are blocked from loopback entirely unless exempted, which
        needs admin (CheckNetIsolation).
    Enforcing all traffic needs a WFP callout, the routing table, or a virtual
    adapter, and every one of those needs elevation. Not possible from here.

    Modes: Run (default) | Stop | Status | SelfTest

    RULES ARE BARE ARGUMENTS. No rules file, nothing to maintain on disk.

      pattern              exact host        example.com
      *.pattern            wildcard, also matches the bare apex
      pattern:port         only that port    api.example.com:443
      a.b.c.d              ipv4 literal      93.184.216.34
      a.b.c.d/len          cidr range        10.20.0.0/16
      pattern=host:port    explicit target   api.example.com=127.0.0.1:9000
      pattern=:port        target port only  api.example.com=:9000
      pattern=port         same              api.example.com=9000

    Use '=' on the command line, not '=>'. The '>' is a redirection operator in
    both cmd and powershell and needs quoting to survive. '=>' and '->' still work
    if you quote the whole rule. Quote anything containing '*' too - powershell
    leaves it alone but bash and other shells will try to glob it.

    First rule that matches wins, so put the specific ones first.

      .\Invoke-LoopbackRedirect.ps1 ads.example.com "*.tracker.net" -Sink
      .\Invoke-LoopbackRedirect.ps1 api.prod.example.com=127.0.0.1:9000
      .\Invoke-LoopbackRedirect.ps1 10.20.0.0/16 93.184.216.34 -Sink
      .\Invoke-LoopbackRedirect.ps1 -CatchAll -Sink -LogTraffic
      .\Invoke-LoopbackRedirect.ps1 -Mode SelfTest

    Calling through 'pwsh -File' can only pass one token per parameter, so use
    commas there:  pwsh -File .\Invoke-LoopbackRedirect.ps1 -Redirect a.com,b.com

    Run SelfTest first if you've touched the rule engine.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [ValidateSet('Run', 'Stop', 'Status', 'SelfTest')]
    [string] $Mode = 'Run',

    # Rules are just bare arguments: .\Invoke-LoopbackRedirect.ps1 a.com *.b.net
    # ValueFromRemainingArguments collects them all, so no -Redirect needed and no
    # rules file. Also accepts -Redirect a.com,b.com if you prefer it explicit.
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]] $Redirect = @(),

    [ValidateRange(1, 65535)]
    [int] $ProxyPort = 8080,

    [switch] $CatchAll,

    [switch] $EnableDnsServer,

    [ValidateRange(1, 65535)]
    [int] $DnsPort = 53,

    [string] $UpstreamDns = '1.1.1.1',

    # socks catches everything tcp, not just http. on by default.
    [switch] $NoSocks,

    [ValidateRange(1, 65535)]
    [int] $SocksPort = 1080,

    [switch] $Sink,

    [int[]] $SinkPorts = @(80, 8000),

    [switch] $NoSystemProxy,

    # HKCU\Environment proxy vars, for the tools that ignore the registry.
    [switch] $NoEnvProxy,

    # Start a program with the proxy vars already in its environment. The registry
    # ones only reach processes launched after the broadcast, this doesn't wait.
    [string] $Launch,

    [string] $LaunchArgs,

    # turn off an existing PAC/WPAD config that would otherwise take priority.
    # checkpointed and put back on exit.
    [switch] $OverridePac,

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

#region rule engine
# NOTE: everything in this region gets injected into the worker runspaces, so keep
# it self contained - no script-scope variables, no imports.

function ConvertTo-IPv4UInt32 {
    param([Parameter(Mandatory)][System.Net.IPAddress] $Address)
    $b = $Address.GetAddressBytes()
    if ($b.Length -ne 4) { return $null }
    return [uint32](([uint32]$b[0] -shl 24) -bor ([uint32]$b[1] -shl 16) -bor ([uint32]$b[2] -shl 8) -bor [uint32]$b[3])
}

function Expand-RuleArguments {
    # Everything unbound lands here, which is convenient but means a mistyped
    # parameter would quietly become a "rule" and the real setting would keep its
    # default. Catch the two shapes that happen in practice and fail loudly.
    param([string[]] $Raw)

    $out = New-Object System.Collections.Generic.List[string]
    foreach ($item in $Raw) {
        if ($null -eq $item) { continue }
        $t = "$item".Trim()
        if (-not $t) { continue }

        if ($t -match '^-{1,2}[A-Za-z]') {
            throw "'$t' looks like a parameter name, not a rule. Check the spelling: Get-Help .\Invoke-LoopbackRedirect.ps1"
        }
        if ($t -match '^\d+$') {
            throw "'$t' is a bare number, not a rule. Multi-value parameters need commas, e.g. -SinkPorts 80,8000"
        }

        # one string may carry several rules when called through -File, which can
        # only pass a single token per parameter
        foreach ($part in ($t -split ',')) {
            $q = $part.Trim()
            if ($q) { $out.Add($q) }
        }
    }
    return $out.ToArray()
}

function New-RedirectRule {
    # parsed once at startup so the match path stays cheap
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

    # optional :port on the pattern. safe to split on the colon since neither ipv4
    # nor hostnames contain one.
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

        # do the mask in 64-bit and truncate. two traps: -shl on a uint32 promotes to
        # int and sign-extends the top bit, and 0xFFFFFFFF is typed Int32 so it comes
        # out as -1 rather than 4294967295. hence the decimal constant.
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

    # *.example.com should hit example.com too, that's what people mean by it
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
    # first match wins
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
    # Interlocked won't take a [ref] into a hashtable member, so lock SyncRoot
    param($Ctx, [string] $Name)
    [System.Threading.Monitor]::Enter($Ctx.Counters.SyncRoot)
    try { $Ctx.Counters[$Name] = [int]$Ctx.Counters[$Name] + 1 }
    finally { [System.Threading.Monitor]::Exit($Ctx.Counters.SyncRoot) }
}

function Write-Log {
    # workers must not write to the console from a runspace - main loop drains this
    param($Ctx, [string] $Level, [string] $Message)
    $stamp = (Get-Date).ToString('HH:mm:ss.fff')
    $Ctx.Log.Enqueue("$stamp|$Level|$Message")
}

function Find-HeaderEnd {
    # index one past the CRLFCRLF, or -1. some clients still send bare LFs.
    param([byte[]] $Buffer, [int] $Length)
    for ($i = 0; $i -lt $Length; $i++) {
        if ($Buffer[$i] -ne 10) { continue }
        if ($i -ge 3 -and $Buffer[$i - 1] -eq 13 -and $Buffer[$i - 2] -eq 10 -and $Buffer[$i - 3] -eq 13) { return $i + 1 }
        if ($i -ge 1 -and $Buffer[$i - 1] -eq 10) { return $i + 1 }
    }
    return -1
}

function Read-Exact {
    # socks framing is length driven, a short read here desyncs the whole stream
    param($Stream, [int] $Count)
    if ($Count -le 0) { return , (New-Object byte[] 0) }
    $buf = New-Object byte[] $Count
    $off = 0
    while ($off -lt $Count) {
        $n = $Stream.Read($buf, $off, $Count - $off)
        if ($n -le 0) { return $null }
        $off += $n
    }
    return , $buf
}

function Copy-Duplex {
    # blind byte pump. this is why CONNECT works without us decrypting anything.
    param($StreamA, $StreamB, [int] $IdleMs = 300000)
    try {
        $t1 = $StreamA.CopyToAsync($StreamB)
        $t2 = $StreamB.CopyToAsync($StreamA)
        [void][System.Threading.Tasks.Task]::WaitAny(@($t1, $t2), $IdleMs)
        [void][System.Threading.Tasks.Task]::WaitAll(@($t1, $t2), 2000)
    }
    catch { }   # either end resetting is a normal way for a tunnel to end
}
#endregion

#region proxy registration
function Update-WinInetSettings {
    # 39 = SETTINGS_CHANGED, 37 = REFRESH. skip these and open apps keep the old proxy.
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
    param([string] $Name, [string] $Path = $script:RegPath)
    try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return $null }
}

# WinINET resolves a proxy in this order: AutoDetect (WPAD), then AutoConfigURL
# (.pac), then the static ProxyServer string. We only ever set the last one.
#
# Still have to check the other two though. If either is already configured on the
# box it wins, our value never gets read, and the script looks like it's working
# while nothing is actually redirected. lost an afternoon to that one.
$script:PacValueNames = @('AutoConfigURL', 'AutoDetect')
# not Join-Path - it tries to resolve the HKCU: drive and throws when the provider
# isn't loaded (bites you on PS Core)
$script:ConnectionsPath = $script:RegPath + '\Connections'

function Set-ProxyRegValue {
    # all config writes go through here so PAC values cannot creep back in
    param([Parameter(Mandatory)][string] $Name, [Parameter(Mandatory)] $Value, [ValidateSet('String', 'DWord')][string] $Type = 'String')

    if ($script:PacValueNames -contains $Name) {
        throw "Refusing to write '$Name'. This script does not use PAC or WPAD auto-configuration; only the static ProxyServer value is used."
    }
    if (-not (Test-Path $script:RegPath)) { New-Item -Path $script:RegPath -Force | Out-Null }
    Set-ItemProperty -Path $script:RegPath -Name $Name -Value $Value -Type $Type
}

function Restore-ProxyRegValue {
    # restore only. allowed to put AutoConfigURL back because that's the user's own
    # value coming out of the checkpoint, not something we invented.
    param([Parameter(Mandatory)][string] $Name, $Value, [ValidateSet('String', 'DWord')][string] $Type = 'String')
    if ($null -ne $Value) { Set-ItemProperty -Path $script:RegPath -Name $Name -Value $Value -Type $Type }
    else { Remove-ItemProperty -Path $script:RegPath -Name $Name -ErrorAction SilentlyContinue }
}

# WinINET also mirrors the mode into a binary blob under ...\Connections.
# [0..3] version, [4..7] change counter, [8..11] flags, then length-prefixed
# strings. We only touch the flags and the counter.
$script:CF_DIRECT = [uint32]0x01
$script:CF_PROXY = [uint32]0x02
$script:CF_PAC = [uint32]0x04
$script:CF_WPAD = [uint32]0x08

function ConvertTo-ConnectionFlagText {
    param([uint32] $Flags)
    $n = @()
    if ($Flags -band $script:CF_DIRECT) { $n += 'Direct' }
    if ($Flags -band $script:CF_PROXY) { $n += 'StaticProxy' }
    if ($Flags -band $script:CF_PAC) { $n += 'PacScript' }
    if ($Flags -band $script:CF_WPAD) { $n += 'WpadAutoDetect' }
    if ($n.Count -eq 0) { $n = @('None') }
    return ($n -join '+')
}

function Get-ConnectionFlags {
    param([byte[]] $Blob)
    if ($null -eq $Blob -or $Blob.Length -lt 12) { return $null }
    return [System.BitConverter]::ToUInt32($Blob, 8)
}

function Edit-ConnectionBlob {
    # returns a copy: clears the PAC + WPAD bits, sets the static proxy bit, bumps counter
    param([byte[]] $Blob)
    if ($null -eq $Blob -or $Blob.Length -lt 12) { return $null }

    $out = New-Object byte[] $Blob.Length
    [Array]::Copy($Blob, $out, $Blob.Length)

    # decimal, not 0xFFFFFFF3 - see the Int32 note in New-RedirectRule
    $clearPacAndWpad = [uint32]4294967283
    $flags = [System.BitConverter]::ToUInt32($out, 8)
    $flags = [uint32]($flags -band $clearPacAndWpad)
    $flags = [uint32]($flags -bor $script:CF_PROXY)
    [System.BitConverter]::GetBytes($flags).CopyTo($out, 8)

    $counter = [System.BitConverter]::ToUInt32($out, 4)
    $counter = [uint32]((([uint64]$counter) + 1) -band [uint64]4294967295)
    [System.BitConverter]::GetBytes($counter).CopyTo($out, 4)

    return $out
}

function Test-PacConfiguration {
    # read only
    if (-not $script:OnWindows) {
        return [pscustomobject]@{ Active = $false; AutoConfigURL = $null; AutoDetect = $null; Flags = $null; FlagText = 'n/a' }
    }
    $url = Get-RegValueOrNull 'AutoConfigURL'
    $det = Get-RegValueOrNull 'AutoDetect'
    $blob = Get-RegValueOrNull 'DefaultConnectionSettings' -Path $script:ConnectionsPath
    $flags = if ($blob) { Get-ConnectionFlags -Blob ([byte[]]$blob) } else { $null }

    $active = [bool]$url -or ($det -eq 1)
    if ($null -ne $flags -and ($flags -band ($script:CF_PAC -bor $script:CF_WPAD))) { $active = $true }

    return [pscustomobject]@{
        Active        = $active
        AutoConfigURL = $url
        AutoDetect    = $det
        Flags         = $flags
        FlagText      = $(if ($null -ne $flags) { ConvertTo-ConnectionFlagText -Flags $flags } else { '(no blob)' })
    }
}

function Clear-PacConfiguration {
    # only ever deletes or clears bits, never writes a PAC. checkpoint runs before this.
    Remove-ItemProperty -Path $script:RegPath -Name 'AutoConfigURL' -ErrorAction SilentlyContinue
    Set-ItemProperty    -Path $script:RegPath -Name 'AutoDetect' -Value 0 -Type DWord -ErrorAction SilentlyContinue

    $blob = Get-RegValueOrNull 'DefaultConnectionSettings' -Path $script:ConnectionsPath
    if ($blob) {
        $edited = Edit-ConnectionBlob -Blob ([byte[]]$blob)
        if ($edited) {
            Set-ItemProperty -Path $script:ConnectionsPath -Name 'DefaultConnectionSettings' -Value $edited -Type Binary -ErrorAction SilentlyContinue
        }
    }
}

$script:EnvPath = 'HKCU:\Environment'
# lowercase on purpose. curl refuses to honour an UPPERCASE HTTP_PROXY at all
# (httpoxy, CVE-2016-5385) and msys/cygwin builds of git and curl do case
# sensitive getenv. windows native lookups are case insensitive so they still find
# these, and the registry itself is case insensitive so restore matches either way.
$script:EnvNames = @('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy', 'JAVA_TOOL_OPTIONS')

# curl, python-requests, node, go and java don't look at the WinINET registry at
# all - they read these. Without them the proxy only ever sees browser traffic.
function Update-EnvironmentBroadcast {
    if (-not $script:OnWindows) { return }
    try {
        if (-not ('LoopbackRedirect.Win32' -as [type])) {
            Add-Type -Namespace 'LoopbackRedirect' -Name 'Win32' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
public static extern System.IntPtr SendMessageTimeout(System.IntPtr hWnd, uint Msg, System.IntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out System.IntPtr lpdwResult);
'@
        }
        $res = [IntPtr]::Zero
        # HWND_BROADCAST, WM_SETTINGCHANGE, SMTO_ABORTIFHUNG
        [void][LoopbackRedirect.Win32]::SendMessageTimeout([IntPtr]0xFFFF, 0x1A, [IntPtr]::Zero, 'Environment', 2, 3000, [ref]$res)
    }
    catch { }
}

function Get-EnvCheckpoint {
    $h = @{}
    foreach ($k in $script:EnvNames) { $h[$k] = Get-RegValueOrNull -Name $k -Path $script:EnvPath }
    return $h
}

function Set-UserEnvProxy {
    param([string] $HttpUrl, [string] $SocksUrl, [string] $Bypass)
    if (-not $script:OnWindows) { return }
    if (-not (Test-Path $script:EnvPath)) { New-Item -Path $script:EnvPath -Force | Out-Null }

    $vals = @{
        http_proxy  = $HttpUrl
        https_proxy = $HttpUrl
        no_proxy    = $Bypass
    }
    # socks5h, not socks5 - the h makes the client hand us the hostname instead of
    # resolving it first, so the name rules still get a chance to match
    if ($SocksUrl) { $vals['all_proxy'] = $SocksUrl }

    $u = [Uri]$HttpUrl
    $vals['JAVA_TOOL_OPTIONS'] = "-Dhttp.proxyHost=$($u.Host) -Dhttp.proxyPort=$($u.Port) -Dhttps.proxyHost=$($u.Host) -Dhttps.proxyPort=$($u.Port)"

    foreach ($k in $vals.Keys) {
        Set-ItemProperty -Path $script:EnvPath -Name $k -Value ([string]$vals[$k]) -Type String
    }
    Update-EnvironmentBroadcast
    Write-Host '  [+] user env vars set (http_proxy, https_proxy, all_proxy, JAVA_TOOL_OPTIONS)' -ForegroundColor Green
    Write-Host '      only affects processes started from now on' -ForegroundColor DarkGray
}

function Restore-UserEnvProxy {
    param($Saved)
    if (-not $script:OnWindows -or -not $Saved) { return }
    foreach ($k in $script:EnvNames) {
        $v = $Saved.$k
        if ($null -ne $v -and "$v" -ne '') { Set-ItemProperty -Path $script:EnvPath -Name $k -Value ([string]$v) -Type String }
        else { Remove-ItemProperty -Path $script:EnvPath -Name $k -ErrorAction SilentlyContinue }
    }
    Update-EnvironmentBroadcast
    Write-Host '  [+] user env vars restored.' -ForegroundColor Green
}

function Register-UserProxy {
    param([string] $Server, [string] $Bypass, [switch] $OverridePac, [switch] $WithEnv, [string] $SocksUrl)
    if (-not $script:OnWindows) {
        Write-Warning 'Not running on Windows - skipping system proxy registration.'
        return
    }

    $blob = Get-RegValueOrNull 'DefaultConnectionSettings' -Path $script:ConnectionsPath

    $checkpoint = [pscustomobject]@{
        SavedAtUtc     = (Get-Date).ToUniversalTime().ToString('o')
        ProxyEnable    = Get-RegValueOrNull 'ProxyEnable'
        ProxyServer    = Get-RegValueOrNull 'ProxyServer'
        ProxyOverride  = Get-RegValueOrNull 'ProxyOverride'
        AutoConfigURL  = Get-RegValueOrNull 'AutoConfigURL'
        AutoDetect     = Get-RegValueOrNull 'AutoDetect'
        ConnectionBlob = $(if ($blob) { [Convert]::ToBase64String([byte[]]$blob) } else { $null })
        PacCleared     = [bool]$OverridePac
        EnvSet         = [bool]$WithEnv
        Env            = $(if ($WithEnv) { Get-EnvCheckpoint } else { $null })
        Pid            = $PID
    }
    $checkpoint | ConvertTo-Json | Set-Content -Path $script:StateFile -Encoding UTF8

    Set-ProxyRegValue -Name 'ProxyServer'   -Value $Server -Type String
    Set-ProxyRegValue -Name 'ProxyOverride' -Value $Bypass -Type String
    Set-ProxyRegValue -Name 'ProxyEnable'   -Value 1 -Type DWord

    if ($OverridePac) {
        Clear-PacConfiguration
        Write-Host '  [+] PAC/WPAD auto-configuration disabled for this session (checkpointed).' -ForegroundColor Green
    }

    Update-WinInetSettings
    Write-Host "  [+] HKCU static proxy set to $Server (bypass: $Bypass)" -ForegroundColor Green

    if ($WithEnv) { Set-UserEnvProxy -HttpUrl "http://$Server" -SocksUrl $SocksUrl -Bypass '' }
}

function Unregister-UserProxy {
    # put HKCU back how we found it
    if (-not $script:OnWindows) { return }
    if (-not (Test-Path $script:StateFile)) {
        Write-Host '  [i] No checkpoint file found; leaving proxy settings alone.' -ForegroundColor DarkGray
        return
    }
    try {
        $cp = Get-Content -Path $script:StateFile -Raw | ConvertFrom-Json

        Restore-ProxyRegValue -Name 'ProxyEnable'   -Value $(if ($null -ne $cp.ProxyEnable) { [int]$cp.ProxyEnable } else { $null }) -Type DWord
        Restore-ProxyRegValue -Name 'ProxyServer'   -Value $(if ($null -ne $cp.ProxyServer) { [string]$cp.ProxyServer } else { $null }) -Type String
        Restore-ProxyRegValue -Name 'ProxyOverride' -Value $(if ($null -ne $cp.ProxyOverride) { [string]$cp.ProxyOverride } else { $null }) -Type String

        if ($cp.PacCleared) {
            # put their PAC/WPAD config back exactly as found
            Restore-ProxyRegValue -Name 'AutoConfigURL' -Value $(if ($null -ne $cp.AutoConfigURL) { [string]$cp.AutoConfigURL } else { $null }) -Type String
            Restore-ProxyRegValue -Name 'AutoDetect'    -Value $(if ($null -ne $cp.AutoDetect) { [int]$cp.AutoDetect } else { $null }) -Type DWord
            if ($cp.ConnectionBlob) {
                $orig = [Convert]::FromBase64String([string]$cp.ConnectionBlob)
                Set-ItemProperty -Path $script:ConnectionsPath -Name 'DefaultConnectionSettings' -Value $orig -Type Binary -ErrorAction SilentlyContinue
            }
            Write-Host '  [+] PAC/WPAD configuration restored.' -ForegroundColor Green
        }

        if ($cp.EnvSet) { Restore-UserEnvProxy -Saved $cp.Env }

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

#region proxy worker
$ProxyWorker = {
    param($Client, $Ctx)

    $clientStream = $null
    $remote = $null
    $peer = '?'
    try {
        $peer = $Client.Client.RemoteEndPoint.ToString()
        #$sw = [Diagnostics.Stopwatch]::StartNew()   # uncomment when latency needs a look
        $Client.NoDelay = $true
        $Client.ReceiveTimeout = 20000
        $Client.SendTimeout = 20000
        $clientStream = $Client.GetStream()

        # read the head without eating any of the body
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
        # whatever the client pipelined after the head gets forwarded as-is
        $leftover = New-Object byte[] ($raw.Length - $headEnd)
        if ($leftover.Length -gt 0) { [Array]::Copy($raw, $headEnd, $leftover, 0, $leftover.Length) }

        $lines = $headText -split "`r?`n"
        $requestLine = $lines[0]
        $parts = $requestLine -split '\s+'
        if ($parts.Count -lt 3) { return }
        $method = $parts[0].ToUpperInvariant()
        $target = $parts[1]
        $version = $parts[2]

        # where does the client actually want to go
        $destHost = $null; $destPort = 0; $originPath = $null
        if ($method -eq 'CONNECT') {
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
            # absolute form - what a client sends when it knows it's talking to a proxy
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
            # origin form - something has pointed at us as if we were the origin
            # server. fall back to the Host header rather than just erroring out.
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

        # timeouts off once we're tunnelling. leave them on and a long idle
        # connection (websocket, streaming) gets torn down mid-flight.
        $remote.ReceiveTimeout = 0
        $remote.SendTimeout = 0
        $Client.ReceiveTimeout = 0
        $Client.SendTimeout = 0
        $remoteStream = $remote.GetStream()

        if ($method -eq 'CONNECT') {
            # say ok and get out of the way. we never decrypt - TLS is negotiated end
            # to end between the client and whatever is on the loopback port.
            $ok = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 Connection Established`r`nProxy-Agent: LoopbackRedirect`r`n`r`n")
            $clientStream.Write($ok, 0, $ok.Length)
            $clientStream.Flush()
            if ($leftover.Length -gt 0) { $remoteStream.Write($leftover, 0, $leftover.Length) }
        }
        else {
            # absolute form -> origin form. we're handing this to an origin server,
            # not an upstream proxy, and it'll reject the absolute URI.
            $rebuilt = New-Object System.Text.StringBuilder
            [void]$rebuilt.Append("$method $originPath $version`r`n")
            $headerLines = if ($lines.Count -gt 1) { $lines[1..($lines.Count - 1)] } else { @() }
            foreach ($line in $headerLines) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                $name = ($line -split ':', 2)[0].Trim().ToLowerInvariant()
                # hop-by-hop, don't forward
                if ($name -in @('proxy-connection', 'proxy-authorization', 'connection', 'keep-alive', 'te', 'trailer', 'upgrade')) { continue }
                [void]$rebuilt.Append("$line`r`n")
            }
            # one request per connection. tried keeping it alive and it goes wrong the
            # moment a client pipelines a request for a different host down the same
            # socket - we'd send it to the previous destination.
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

#region socks

# RFC 1928 (and 1928's predecessor socks4/4a, which some older tooling still speaks).
# The point of having this at all: an HTTP proxy only understands HTTP verbs and
# CONNECT. Socks is protocol agnostic, so anything that can speak it - git, ssh,
# irc/xmpp clients, torrent clients, browsers via --proxy-server=socks5:// - can be
# redirected too, not just web traffic.
#
# CONNECT only. BIND and UDP ASSOCIATE return "command not supported"; UDP would
# need a whole second datagram path and nothing I care about asks for it.
$SocksWorker = {
    param($Client, $Ctx)

    $remote = $null
    try {
        $Client.NoDelay = $true
        $Client.ReceiveTimeout = 20000
        $Client.SendTimeout = 20000
        $s = $Client.GetStream()

        # NB: compare against $null, never -not. [bool] on a single element array
        # tests the element, so a byte[] holding 0x00 is falsy - which silently ate
        # the "05 01 00" greeting that most socks clients send.
        $ver = Read-Exact -Stream $s -Count 1
        if ($null -eq $ver) { return }

        $destHost = $null
        $destPort = 0
        $proto = ''

        if ($ver[0] -eq 5) {
            $proto = 'socks5'

            # greeting: nmethods, then that many method bytes
            $nm = Read-Exact -Stream $s -Count 1
            if ($null -eq $nm) { return }
            $methods = Read-Exact -Stream $s -Count ([int]$nm[0])
            if ($null -eq $methods) { return }
            if ($methods -notcontains ([byte]0)) {
                $s.Write([byte[]]@(5, 0xFF), 0, 2)      # no auth method we can do
                Write-Log -Ctx $Ctx -Level 'SOCKS' -Message 'client offered no usable auth method'
                return
            }
            $s.Write([byte[]]@(5, 0), 0, 2)             # no auth required
            $s.Flush()

            # request: ver, cmd, rsv, atyp
            $req = Read-Exact -Stream $s -Count 4
            if ($null -eq $req) { return }
            $cmd = [int]$req[1]
            $atyp = [int]$req[3]

            if ($atyp -eq 1) {
                $a = Read-Exact -Stream $s -Count 4
                if ($null -eq $a) { return }
                $destHost = '{0}.{1}.{2}.{3}' -f $a[0], $a[1], $a[2], $a[3]
            }
            elseif ($atyp -eq 3) {
                $l = Read-Exact -Stream $s -Count 1
                if ($null -eq $l) { return }
                $a = Read-Exact -Stream $s -Count ([int]$l[0])
                if ($null -eq $a) { return }
                $destHost = [Text.Encoding]::ASCII.GetString($a)
            }
            elseif ($atyp -eq 4) {
                $a = Read-Exact -Stream $s -Count 16
                if ($null -eq $a) { return }
                $destHost = (New-Object System.Net.IPAddress (, $a)).ToString()
            }
            else {
                $s.Write([byte[]]@(5, 8, 0, 1, 0, 0, 0, 0, 0, 0), 0, 10)   # atyp not supported
                return
            }

            $pb = Read-Exact -Stream $s -Count 2
            if ($null -eq $pb) { return }
            $destPort = ([int]$pb[0] -shl 8) -bor [int]$pb[1]

            if ($cmd -ne 1) {
                $s.Write([byte[]]@(5, 7, 0, 1, 0, 0, 0, 0, 0, 0), 0, 10)   # cmd not supported
                Write-Log -Ctx $Ctx -Level 'SOCKS' -Message "cmd $cmd not supported (connect only)"
                return
            }
        }
        elseif ($ver[0] -eq 4) {
            $proto = 'socks4'
            $h = Read-Exact -Stream $s -Count 7        # cmd(1) port(2) ip(4)
            if ($null -eq $h) { return }
            $cmd = [int]$h[0]
            $destPort = ([int]$h[1] -shl 8) -bor [int]$h[2]

            # 0.0.0.x with x nonzero is the socks4a marker: hostname follows the userid
            $is4a = ($h[3] -eq 0 -and $h[4] -eq 0 -and $h[5] -eq 0 -and $h[6] -ne 0)

            while ($true) {                            # discard userid
                $b = Read-Exact -Stream $s -Count 1
                if ($null -eq $b -or $b[0] -eq 0) { break }
            }

            if ($is4a) {
                $sb = New-Object System.Text.StringBuilder
                while ($true) {
                    $b = Read-Exact -Stream $s -Count 1
                    if ($null -eq $b -or $b[0] -eq 0) { break }
                    [void]$sb.Append([char]$b[0])
                }
                $destHost = $sb.ToString()
            }
            else {
                $destHost = '{0}.{1}.{2}.{3}' -f $h[3], $h[4], $h[5], $h[6]
            }

            if ($cmd -ne 1) {
                $s.Write([byte[]]@(0, 0x5B, 0, 0, 0, 0, 0, 0), 0, 8)
                return
            }
        }
        else { return }

        if (-not $destHost) { return }
        $destHost = $destHost.TrimEnd('.')

        $dest = Resolve-Destination -TargetHost $destHost -TargetPort $destPort -Ctx $Ctx
        if ($dest.Redirected) {
            Add-Counter -Ctx $Ctx -Name 'Redirected'
            Write-Log -Ctx $Ctx -Level 'REDIR' -Message ("{0} {1}:{2} -> {3}:{4}  [{5}]" -f $proto, $destHost, $destPort, $dest.Host, $dest.Port, $dest.Rule)
        }
        else {
            Add-Counter -Ctx $Ctx -Name 'Passed'
            if ($Ctx.LogTraffic) { Write-Log -Ctx $Ctx -Level 'PASS ' -Message ("{0} {1}:{2}" -f $proto, $destHost, $destPort) }
        }

        $remote = New-Object System.Net.Sockets.TcpClient
        $remote.NoDelay = $true
        $connected = $true
        try {
            $c = $remote.ConnectAsync($dest.Host, $dest.Port)
            if (-not $c.Wait(10000)) { throw 'timed out' }
            if ($c.IsFaulted) { throw $c.Exception.GetBaseException().Message }
        }
        catch {
            $connected = $false
            Write-Log -Ctx $Ctx -Level 'FAIL ' -Message ("{0}:{1} unreachable - {2}" -f $dest.Host, $dest.Port, $_.Exception.Message)
        }

        if (-not $connected) {
            if ($proto -eq 'socks5') { $s.Write([byte[]]@(5, 5, 0, 1, 0, 0, 0, 0, 0, 0), 0, 10) }
            else { $s.Write([byte[]]@(0, 0x5B, 0, 0, 0, 0, 0, 0), 0, 8) }
            return
        }

        # success reply carries the bound address; hand back the local end of the
        # socket we just opened rather than faking zeros
        $bndIp = [byte[]]@(0, 0, 0, 0)
        $bndPort = 0
        try {
            $lep = $remote.Client.LocalEndPoint
            if ($lep.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                $bndIp = $lep.Address.GetAddressBytes()
                $bndPort = $lep.Port
            }
        }
        catch { }

        if ($proto -eq 'socks5') {
            $rep = [byte[]]@(5, 0, 0, 1) + $bndIp + @([byte](($bndPort -shr 8) -band 0xFF), [byte]($bndPort -band 0xFF))
        }
        else {
            $rep = [byte[]]@(0, 0x5A, [byte](($bndPort -shr 8) -band 0xFF), [byte]($bndPort -band 0xFF)) + $bndIp
        }
        $s.Write($rep, 0, $rep.Length)
        $s.Flush()

        $remote.ReceiveTimeout = 0
        $remote.SendTimeout = 0
        $Client.ReceiveTimeout = 0
        $Client.SendTimeout = 0

        Copy-Duplex -StreamA $s -StreamB $remote.GetStream()
    }
    catch {
        try { Write-Log -Ctx $Ctx -Level 'ERR  ' -Message ("socks - {0}" -f $_.Exception.Message) } catch { }
    }
    finally {
        if ($remote) { try { $remote.Close() } catch { } }
        if ($Client) { try { $Client.Close() } catch { } }
    }
}
#endregion

#region sink
$SinkWorker = {
    param($Client, $Ctx, $LocalPort)
    try {
        $Client.ReceiveTimeout = 5000
        $s = $Client.GetStream()
        $buf = New-Object byte[] 4096
        $n = 0
        try { $n = $s.Read($buf, 0, $buf.Length) } catch { }
        $first = if ($n -gt 0) { ([Text.Encoding]::ASCII.GetString($buf, 0, $n) -split "`r?`n")[0] } else { '(no data)' }

        # 0x16 0x03 = TLS ClientHello. answering that with an HTTP error just gives
        # the client a confusing parse failure, so close instead.
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

#region dns
$DnsWorker = {
    param($Ctx)

    # 12 byte header: 0-1 id, 2-3 flags, 4-5 qdcount, 6-7 ancount, 8-9 nscount,
    # 10-11 arcount. then the question: length-prefixed labels, 0x00 terminator,
    # qtype and qclass as 16-bit BE.
    # TODO: this loop is single threaded, so a slow upstream stalls every other
    # query behind it. the 3s timeout keeps it bounded. fine for a handful of
    # clients, would need reworking if it ever fronted anything real.
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

            # decode qname
            $i = 12
            $labels = New-Object System.Collections.Generic.List[string]
            $bad = $false
            while ($true) {
                if ($i -ge $data.Length) { $bad = $true; break }
                $len = [int]$data[$i]
                if ($len -eq 0) { $i++; break }
                if (($len -band 0xC0) -ne 0) { $bad = $true; break }   # pointer in a question, malformed
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
                # build the answer ourselves
                $resp = New-Object System.Collections.Generic.List[byte]
                for ($k = 0; $k -lt $questionEnd; $k++) { $resp.Add($data[$k]) }

                # qr=1, keep opcode and rd, set aa
                $resp[2] = [byte]((([int]$data[2] -band 0x7F) -bor 0x80) -bor 0x04)
                $resp[3] = [byte]0x80          # RA=1, RCODE=NOERROR
                $resp[6] = [byte]0; $resp[7] = [byte]1     # ANCOUNT = 1
                $resp[8] = [byte]0; $resp[9] = [byte]0     # NSCOUNT = 0
                $resp[10] = [byte]0; $resp[11] = [byte]0   # ARCOUNT = 0

                # 0xC00C = compression pointer back to the qname at offset 12
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

            # everything else goes upstream
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
                # servfail so the client gives up now instead of sitting on its timeout
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

#region selftest
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

    Write-Host "`n  rule matching" -ForegroundColor Cyan

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

    Write-Host "`n  target parsing" -ForegroundColor Cyan
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

    Write-Host "`n  precedence + pass-through" -ForegroundColor Cyan
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

    Write-Host "`n  rule file parsing" -ForegroundColor Cyan
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

    Write-Host "`n  command line argument handling" -ForegroundColor Cyan

    $argCases = @(
        @{ In = @('a.com', 'b.com'); Out = @('a.com', 'b.com'); Why = 'separate args' }
        @{ In = @('a.com,b.com'); Out = @('a.com', 'b.com'); Why = 'comma split for -File' }
        @{ In = @('a.com, b.com , c.com'); Out = @('a.com', 'b.com', 'c.com'); Why = 'comma split trims' }
        @{ In = @('a.com=127.0.0.1:9000'); Out = @('a.com=127.0.0.1:9000'); Why = 'target survives, no comma' }
        @{ In = @('', '   ', 'a.com'); Out = @('a.com'); Why = 'blanks dropped' }
        @{ In = @('10.20.0.0/16'); Out = @('10.20.0.0/16'); Why = 'cidr untouched' }
    )
    foreach ($c in $argCases) {
        $got = @(Expand-RuleArguments -Raw $c.In)
        $ok = ($got.Count -eq $c.Out.Count)
        if ($ok) { for ($z = 0; $z -lt $got.Count; $z++) { if ($got[$z] -ne $c.Out[$z]) { $ok = $false } } }
        if ($ok) {
            $script:pass++; Write-Host ("  PASS  {0,-26} -> {1}" -f ($c.In -join '|'), ($got -join '|')) -ForegroundColor DarkGreen
        }
        else {
            $script:fail++; Write-Host ("  FAIL  {0} -> {1} (wanted {2}) - {3}" -f ($c.In -join '|'), ($got -join '|'), ($c.Out -join '|'), $c.Why) -ForegroundColor Red
        }
    }

    # a mistyped parameter must not silently become a rule
    foreach ($bad in '-ProxyPrt', '--sink', '9999') {
        $threw = $false
        try { [void](Expand-RuleArguments -Raw @($bad)) } catch { $threw = $true }
        if ($threw) {
            $script:pass++; Write-Host ("  PASS  rejects '{0}' instead of treating it as a rule" -f $bad) -ForegroundColor DarkGreen
        }
        else { $script:fail++; Write-Host ("  FAIL  '{0}' was accepted as a rule" -f $bad) -ForegroundColor Red }
    }

    # the '=' form matters most on the command line, '>' needs quoting
    foreach ($f in 'a.com=9000', 'a.com=:9000', 'a.com=127.0.0.1:9000') {
        $r = New-RedirectRule -Line $f
        if ($r -and $r.TargetPort -eq 9000 -and $r.Pattern -eq 'a.com') {
            $script:pass++; Write-Host ("  PASS  unquoted form '{0}' parses" -f $f) -ForegroundColor DarkGreen
        }
        else { $script:fail++; Write-Host ("  FAIL  '{0}' did not parse" -f $f) -ForegroundColor Red }
    }

    Write-Host "`n  pac safety net" -ForegroundColor Cyan

    # must refuse PAC/WPAD names before it touches the registry
    foreach ($forbidden in 'AutoConfigURL', 'AutoDetect') {
        $threw = $false
        try { Set-ProxyRegValue -Name $forbidden -Value 'http://evil/proxy.pac' -Type String }
        catch { $threw = $true }
        if ($threw) {
            $script:pass++; Write-Host ("  PASS  Set-ProxyRegValue refuses '{0}'" -f $forbidden) -ForegroundColor DarkGreen
        }
        else { $script:fail++; Write-Host ("  FAIL  Set-ProxyRegValue accepted '{0}'" -f $forbidden) -ForegroundColor Red }
    }

    $flagCases = @(
        @{ F = 0x02; T = 'StaticProxy' }
        @{ F = 0x0B; T = 'Direct+StaticProxy+WpadAutoDetect' }
        @{ F = 0x07; T = 'Direct+StaticProxy+PacScript' }
        @{ F = 0x01; T = 'Direct' }
    )
    foreach ($c in $flagCases) {
        $got = ConvertTo-ConnectionFlagText -Flags ([uint32]$c.F)
        if ($got -eq $c.T) {
            $script:pass++; Write-Host ("  PASS  flags 0x{0:X2} decodes to {1}" -f $c.F, $got) -ForegroundColor DarkGreen
        }
        else { $script:fail++; Write-Host ("  FAIL  flags 0x{0:X2} -> {1} (expected {2})" -f $c.F, $got, $c.T) -ForegroundColor Red }
    }

    # pac/wpad bits off, static on, counter bumped, everything else left alone
    $blob = New-Object byte[] 32
    [System.BitConverter]::GetBytes([uint32]70).CopyTo($blob, 0)
    [System.BitConverter]::GetBytes([uint32]41).CopyTo($blob, 4)
    [System.BitConverter]::GetBytes([uint32](0x01 -bor 0x04 -bor 0x08)).CopyTo($blob, 8)
    for ($z = 12; $z -lt 32; $z++) { $blob[$z] = [byte]($z) }

    $edited = Edit-ConnectionBlob -Blob $blob
    $newFlags = Get-ConnectionFlags -Blob $edited
    $newCount = [System.BitConverter]::ToUInt32($edited, 4)
    $tailSame = $true
    for ($z = 12; $z -lt 32; $z++) { if ($edited[$z] -ne $blob[$z]) { $tailSame = $false } }

    $checks2 = @(
        @{ Ok = (($newFlags -band 0x04) -eq 0); Msg = 'PAC bit cleared' }
        @{ Ok = (($newFlags -band 0x08) -eq 0); Msg = 'WPAD bit cleared' }
        @{ Ok = (($newFlags -band 0x02) -ne 0); Msg = 'static proxy bit asserted' }
        @{ Ok = (($newFlags -band 0x01) -ne 0); Msg = 'unrelated bits preserved' }
        @{ Ok = ($newCount -eq 42); Msg = 'change counter incremented' }
        @{ Ok = ($edited.Length -eq $blob.Length); Msg = 'blob length unchanged' }
        @{ Ok = $tailSame; Msg = 'trailing payload untouched' }
        @{ Ok = ((Get-ConnectionFlags -Blob $blob) -eq 0x0D); Msg = 'input blob not mutated (pure function)' }
    )
    foreach ($c in $checks2) {
        if ($c.Ok) { $script:pass++; Write-Host ("  PASS  {0}" -f $c.Msg) -ForegroundColor DarkGreen }
        else { $script:fail++; Write-Host ("  FAIL  {0}" -f $c.Msg) -ForegroundColor Red }
    }

    # regression: a byte[] holding a single 0x00 is FALSY in powershell, because
    # [bool] on a one element array tests the element not the array. that silently
    # broke the socks greeting for every client that sends "05 01 00".
    $oneZero = [byte[]]@(0)
    if ((-not $oneZero) -eq $true -and ($null -eq $oneZero) -eq $false) {
        $script:pass++; Write-Host '  PASS  byte[]{0} truthiness trap still behaves as documented' -ForegroundColor DarkGreen
    }
    else { $script:fail++; Write-Host '  FAIL  truthiness assumption changed - recheck the socks parser' -ForegroundColor Red }

    $socksSrc = $SocksWorker.ToString()
    if ($socksSrc -notmatch '-not \$(ver|nm|methods|req|pb)\b') {
        $script:pass++; Write-Host '  PASS  socks parser compares byte arrays against $null' -ForegroundColor DarkGreen
    }
    else { $script:fail++; Write-Host '  FAIL  socks parser uses -not on a byte array' -ForegroundColor Red }

    # no config path may write a PAC. restore is excluded on purpose.
    foreach ($fn in 'Set-ProxyRegValue', 'Register-UserProxy', 'Clear-PacConfiguration') {
        $def = (Get-Command -Name $fn -CommandType Function).Definition
        $writesPac = ($def -match 'Set-ItemProperty[^\r\n]*AutoConfigURL') -or ($def -match 'FindProxyForURL')
        if (-not $writesPac) {
            $script:pass++; Write-Host ("  PASS  {0} authors no PAC" -f $fn) -ForegroundColor DarkGreen
        }
        else { $script:fail++; Write-Host ("  FAIL  {0} writes a PAC configuration" -f $fn) -ForegroundColor Red }
    }

    # Clear-PacConfiguration should only ever remove AutoConfigURL
    $clearDef = (Get-Command -Name 'Clear-PacConfiguration' -CommandType Function).Definition
    if ($clearDef -match 'Remove-ItemProperty[^\r\n]*AutoConfigURL') {
        $script:pass++; Write-Host '  PASS  Clear-PacConfiguration removes AutoConfigURL rather than setting it' -ForegroundColor DarkGreen
    }
    else { $script:fail++; Write-Host '  FAIL  Clear-PacConfiguration does not remove AutoConfigURL' -ForegroundColor Red }

    Write-Host ''
    $color = if ($script:fail -eq 0) { 'Green' } else { 'Red' }
    Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $color
    Write-Host ''
    return ($script:fail -eq 0)
}
#endregion

#region main
function Show-Banner {
    Write-Host ''
    Write-Host '  loopback redirector' -ForegroundColor Cyan
    Write-Host '  redirects to 127.0.0.1, no admin needed' -ForegroundColor DarkGray
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
            Write-Host '  Auto-config (has to be off or the static proxy is ignored)' -ForegroundColor Cyan
            $pac = Test-PacConfiguration
            Write-Host ("    {0,-14} {1}" -f 'AutoConfigURL', $(if ($pac.AutoConfigURL) { $pac.AutoConfigURL } else { '(not set)' }))
            Write-Host ("    {0,-14} {1}" -f 'AutoDetect', $(if ($null -ne $pac.AutoDetect) { $pac.AutoDetect } else { '(not set)' }))
            Write-Host ("    {0,-14} {1}" -f 'Conn flags', $pac.FlagText)
            Write-Host ("    {0,-14} {1}" -f 'PAC/WPAD', $(if ($pac.Active) { 'ACTIVE - overrides the static proxy' } else { 'inactive' })) -ForegroundColor $(if ($pac.Active) { 'Yellow' } else { 'Green' })
            Write-Host ''
            Write-Host ("  Checkpoint file: {0}" -f $(if (Test-Path $script:StateFile) { $script:StateFile } else { '(none)' }))
        }
        else { Write-Host '  Not on Windows - no registry state to report.' -ForegroundColor Yellow }

        Write-Host ''
        Write-Host '  Loopback listeners' -ForegroundColor Cyan
        $probe = @($ProxyPort, $SocksPort) + $SinkPorts | Select-Object -Unique
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

        # build rules
        $ruleLines = @(Expand-RuleArguments -Raw $Redirect)

        $rules = New-Object System.Collections.Generic.List[object]
        foreach ($l in $ruleLines) {
            $rule = New-RedirectRule -Line $l
            if ($rule) { $rules.Add($rule) }
        }

        if ($rules.Count -eq 0 -and -not $CatchAll) {
            Write-Warning 'No rules and no -CatchAll, so every connection would just pass through.'
            Write-Host ''
            Write-Host '  Rules are bare arguments. Quote anything with * or > in it:' -ForegroundColor DarkGray
            Write-Host '    .\Invoke-LoopbackRedirect.ps1 ads.example.com "*.tracker.net" -Sink' -ForegroundColor DarkGray
            Write-Host '    .\Invoke-LoopbackRedirect.ps1 api.example.com=127.0.0.1:9000' -ForegroundColor DarkGray
            Write-Host '    .\Invoke-LoopbackRedirect.ps1 10.20.0.0/16 93.184.216.34 -Sink' -ForegroundColor DarkGray
            Write-Host '    .\Invoke-LoopbackRedirect.ps1 -CatchAll -Sink' -ForegroundColor DarkGray
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

        # shared state for the workers
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

        # runspace pool
        # runspaces don't inherit our functions, so push the rule engine into the
        # InitialSessionState and bind $Ctx as a shared variable
        $shared = 'ConvertTo-IPv4UInt32', 'Test-RuleMatch', 'Resolve-Destination', 'Write-Log', 'Add-Counter',
        'Find-HeaderEnd', 'Copy-Duplex', 'Read-Exact'
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
                # low ports bind fine as a normal user on Windows. it's only
                # HttpListener (http.sys) that wants an admin URL reservation.
                $l.Start(200)
                Write-Host ("  [+] {0} on 127.0.0.1:{1}" -f $Label, $Port) -ForegroundColor Green
                return $l
            }
            catch {
                Write-Host ("  [!] cannot bind 127.0.0.1:{0} - {1}" -f $Port, $_.Exception.Message) -ForegroundColor Red
                Write-Host '      port in use, or caught in a Hyper-V/WSL reserved range:' -ForegroundColor DarkGray
                Write-Host '      netsh int ipv4 show excludedportrange protocol=tcp' -ForegroundColor DarkGray
                return $null
            }
        }

        try {
            Write-Host '  Listeners' -ForegroundColor Cyan
            $proxyListener = Start-LoopbackListener -Port $ProxyPort -Label 'proxy    '
            if (-not $proxyListener) { throw "Could not bind the proxy port $ProxyPort." }

            $socksListener = $null
            if (-not $NoSocks) {
                $socksListener = Start-LoopbackListener -Port $SocksPort -Label 'socks    '
                if ($socksListener) { $listeners.Add($socksListener) }
            }

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

                # WPAD > PAC > static. if either of the first two is on, we write our
                # value and it never gets read. say so instead of pretending.
                $pac = Test-PacConfiguration
                if ($pac.Active) {
                    Write-Host '  [!] This machine already has PAC/WPAD auto-configuration enabled:' -ForegroundColor Yellow
                    if ($pac.AutoConfigURL) { Write-Host ("      AutoConfigURL : {0}" -f $pac.AutoConfigURL) -ForegroundColor Yellow }
                    if ($pac.AutoDetect -eq 1) { Write-Host '      AutoDetect    : 1 (WPAD)' -ForegroundColor Yellow }
                    if ($null -ne $pac.Flags) { Write-Host ("      Conn flags    : 0x{0:X2} = {1}" -f $pac.Flags, $pac.FlagText) -ForegroundColor Yellow }
                    if ($OverridePac) {
                        Write-Host '      -OverridePac given: disabling it for this session.' -ForegroundColor Yellow
                    }
                    else {
                        Write-Host '      That takes priority over the static proxy, so nothing gets redirected.' -ForegroundColor Red
                        Write-Host '      Re-run with -OverridePac, or use -NoSystemProxy and point clients at' -ForegroundColor Red
                        Write-Host ("      127.0.0.1:{0} directly. This script will not author a PAC file." -f $ProxyPort) -ForegroundColor Red
                    }
                }

                $socksUrl = if (-not $NoSocks) { "socks5h://127.0.0.1:$SocksPort" } else { '' }
                Register-UserProxy -Server "127.0.0.1:$ProxyPort" -Bypass $ProxyBypass `
                    -OverridePac:$OverridePac -WithEnv:(-not $NoEnvProxy) -SocksUrl $socksUrl
                $proxyRegistered = $true
                Write-Host ''
            }
            else {
                Write-Host "  [i] -NoSystemProxy: configure clients manually, e.g." -ForegroundColor DarkGray
                Write-Host "      curl -x http://127.0.0.1:$ProxyPort https://example.com" -ForegroundColor DarkGray
                if (-not $NoSocks) {
                    Write-Host "      curl --socks5-hostname 127.0.0.1:$SocksPort https://example.com" -ForegroundColor DarkGray
                }
                Write-Host ''
            }

            if ($Launch) {
                # set them on ourselves first, the child inherits our block. this is
                # the only way to catch an app without waiting for it to be restarted.
                $env:http_proxy = "http://127.0.0.1:$ProxyPort"
                $env:https_proxy = $env:http_proxy
                if (-not $NoSocks) { $env:all_proxy = "socks5h://127.0.0.1:$SocksPort" }
                $env:JAVA_TOOL_OPTIONS = "-Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=$ProxyPort -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=$ProxyPort"
                try {
                    if ($LaunchArgs) { $proc = Start-Process -FilePath $Launch -ArgumentList $LaunchArgs -PassThru }
                    else { $proc = Start-Process -FilePath $Launch -PassThru }
                    Write-Host ("  [+] launched {0} (pid {1}) with proxy env injected" -f $Launch, $proc.Id) -ForegroundColor Green
                }
                catch {
                    Write-Host ("  [!] could not launch {0} - {1}" -f $Launch, $_.Exception.Message) -ForegroundColor Red
                }
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

                # ---- accept socks connections
                if ($socksListener) {
                    while ($socksListener.Pending()) {
                        $client = $socksListener.AcceptTcpClient()
                        $ps = [powershell]::Create()
                        $ps.RunspacePool = $pool
                        [void]$ps.AddScript($SocksWorker).AddArgument($client).AddArgument($Ctx)
                        $jobs.Add([pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke() })
                    }
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
            # this is why it's safe to ctrl+c - HKCU gets put back before we exit
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
