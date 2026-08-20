# =============================================================================
#  LAB / EDUCATIONAL - defensive fraud detection reference model.
#  Do not use against networks you do not own.
# =============================================================================
#
#  zero-rating-detection-lab :: run_demo.ps1
#
#  Native PowerShell equivalent of run_demo.sh, for Windows users without
#  Git Bash. Same three-part story, same output:
#
#     (a) legitimate traffic is charged correctly by the naive classifier
#     (b) SPOOFED traffic fools the naive classifier - the meter fails to bill
#     (c) the SAME spoofed traffic is caught and dropped by the detector
#
#  Written for Windows PowerShell 5.1 compatibility: no '&&' chaining, no
#  ternary operator, no null-coalescing.
#
#  Nothing in this script contacts a network. Every listener and every target
#  is a 127.0.0.0/8 address on this machine.
# =============================================================================

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# --- resolve the interpreter -------------------------------------------------
if (Test-Path ".venv\Scripts\python.exe") {
    $PY = ".\.venv\Scripts\python.exe"
    $MITMDUMP = ".\.venv\Scripts\mitmdump.exe"
} else {
    $pyCmd = Get-Command python -ErrorAction SilentlyContinue
    if ($null -eq $pyCmd) {
        Write-Error "No python interpreter found. See README setup instructions."
        exit 1
    }
    $PY = $pyCmd.Source
    $mitmCmd = Get-Command mitmdump -ErrorAction SilentlyContinue
    if ($null -eq $mitmCmd) {
        Write-Error "mitmdump not found. Run: pip install -r requirements.txt"
        exit 1
    }
    $MITMDUMP = $mitmCmd.Source
}

# Force ANSI colour so the naive-vs-detector contrast survives redirection.
$env:ZRLAB_FORCE_COLOR = "1"
# Belt-and-braces: pin the offline resolver so the demo emits zero DNS queries.
$env:ZRLAB_RESOLVER = "fixture"

# Single source of truth for the topology is lab_config.py.
$cfgLines = & $PY -c @"
import lab_config as c
print(c.PROXY_HOST); print(c.PROXY_PORT)
print(c.ORIGIN_HTTP_PORT); print(c.ORIGIN_HTTPS_PORT)
print(c.ORIGIN_ZERO_RATED_IP); print(c.ORIGIN_CHARGED_IP)
"@
$PROXY_HOST = $cfgLines[0]
$PROXY_PORT = [int]$cfgLines[1]
$HTTP_PORT  = [int]$cfgLines[2]
$HTTPS_PORT = [int]$cfgLines[3]
$ZR_IP      = $cfgLines[4]
$CH_IP      = $cfgLines[5]

$script:OriginProc = $null
$script:ProxyProc = $null

function Stop-LabProcesses {
    foreach ($p in @($script:ProxyProc, $script:OriginProc)) {
        if ($null -ne $p) {
            try {
                if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
            } catch {}
        }
    }
}

function Write-Banner([string]$Text) {
    Write-Host ""
    Write-Host ("=" * 80)
    Write-Host "  $Text"
    Write-Host ("=" * 80)
}

function Test-PortFree([string]$IPAddress, [int]$Port) {
    $listener = $null
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse($IPAddress), $Port)
        $listener.Start()
        return $true
    } catch {
        return $false
    } finally {
        if ($null -ne $listener) { try { $listener.Stop() } catch {} }
    }
}

function Wait-ForPort([string]$IPAddress, [int]$Port, [int]$Tries = 60) {
    for ($i = 0; $i -lt $Tries; $i++) {
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $async = $client.BeginConnect($IPAddress, $Port, $null, $null)
            if ($async.AsyncWaitHandle.WaitOne(400) -and $client.Connected) {
                $client.Close()
                return $true
            }
        } catch {
        } finally {
            try { $client.Close() } catch {}
        }
        Start-Sleep -Milliseconds 250
    }
    return $false
}

function Invoke-Phase([string]$Addon, [string]$Phase, [string]$Label) {
    Write-Banner $Label
    Write-Host "  addon      : $Addon"
    Write-Host "  proxy      : ${PROXY_HOST}:${PROXY_PORT}"
    Write-Host "  scenarios  : legit-charged, legit-zerorated, spoof-http,"
    Write-Host "               legit-zerorated-tls, spoof-tls"
    Write-Host ""

    # --ssl-insecure: the lab origin uses a self-signed local certificate.
    # connection_strategy=eager: connect upstream before replying, so the real
    #   destination is known at request time.
    $mitmArgs = @(
        "-s", $Addon,
        "--listen-host", $PROXY_HOST,
        "--listen-port", $PROXY_PORT,
        "--set", "connection_strategy=eager",
        "--set", "termlog_verbosity=warn",
        "--set", "flow_detail=0",
        "--ssl-insecure"
    )
    # Output is NOT redirected: the addon's charging and detection log lines
    # are the whole point of the demo and belong on screen. mitmproxy's own
    # chatter is already silenced by termlog_verbosity/flow_detail above.
    $script:ProxyProc = Start-Process -FilePath $MITMDUMP -ArgumentList $mitmArgs `
        -NoNewWindow -PassThru

    if (-not (Wait-ForPort $PROXY_HOST $PROXY_PORT)) {
        Write-Host "ERROR: proxy did not come up (see the mitmdump output above)." -ForegroundColor Red
        Stop-LabProcesses
        exit 1
    }

    & $PY attacker_client.py --phase $Phase --shutdown-proxy

    # --shutdown-proxy asks the addon to stop gracefully so it writes its final
    # CCR-T and meter report. Give it a moment, then insist.
    for ($i = 0; $i -lt 20; $i++) {
        if ($script:ProxyProc.HasExited) { break }
        Start-Sleep -Milliseconds 250
    }
    if (-not $script:ProxyProc.HasExited) {
        Stop-Process -Id $script:ProxyProc.Id -Force -ErrorAction SilentlyContinue
    }
    $script:ProxyProc = $null
}

# =============================================================================
#  Go
# =============================================================================
try {
    Write-Banner "ZERO-RATING BYPASS DETECTION LAB"
    Write-Host @"
  Simplified reference model built from public 3GPP concepts: traffic
  classification feeds charging rules, the packet gateway (PCEF) meters usage
  to the OCS over the Diameter Gy interface (cf. 3GPP TS 32.299, TS 32.240).

  This is NOT any operator's production system and contains no operator data.
  Every listener and every target below is a 127.0.0.0/8 loopback address.
  Nothing in this demo touches, probes, or depends on a real network.
"@

    # Fresh evidence for every run.
    if (Test-Path "logs") { Remove-Item -Recurse -Force "logs" }
    New-Item -ItemType Directory -Path "logs" | Out-Null

    # --- pre-flight: are the ports we need actually free? --------------------
    $busy = @()
    if (-not (Test-PortFree $PROXY_HOST $PROXY_PORT)) {
        $busy += "  ${PROXY_HOST}:${PROXY_PORT}  [proxy (ZRLAB_PROXY_PORT)]"
    }
    foreach ($ip in @($ZR_IP, $CH_IP)) {
        if (-not (Test-PortFree $ip $HTTP_PORT))  { $busy += "  ${ip}:${HTTP_PORT}  [origin http (ZRLAB_HTTP_PORT)]" }
        if (-not (Test-PortFree $ip $HTTPS_PORT)) { $busy += "  ${ip}:${HTTPS_PORT}  [origin https (ZRLAB_HTTPS_PORT)]" }
    }
    if ($busy.Count -gt 0) {
        Write-Host "ERROR: these lab ports are not available:" -ForegroundColor Red
        $busy | ForEach-Object { Write-Host $_ }
        Write-Host ""
        Write-Host 'Override them, e.g.:'
        Write-Host '  $env:ZRLAB_PROXY_PORT=19081; $env:ZRLAB_HTTP_PORT=19080; $env:ZRLAB_HTTPS_PORT=19443; .\run_demo.ps1'
        exit 1
    }

    Write-Banner "STEP 0 - start the local origin server (loopback only)"
    $script:OriginProc = Start-Process -FilePath $PY `
        -ArgumentList @("local_test_server.py") -NoNewWindow -PassThru
    if (-not (Wait-ForPort $CH_IP $HTTP_PORT) -or -not (Wait-ForPort $ZR_IP $HTTPS_PORT)) {
        Write-Host "ERROR: local origin failed to start. See logs\local_test_server.jsonl" -ForegroundColor Red
        exit 1
    }
    Write-Host "  ${ZR_IP}:$HTTP_PORT/$HTTPS_PORT  = genuine zero-rated service (zoom.us in dns_fixtures.json)"
    Write-Host "  ${CH_IP}:$HTTP_PORT/$HTTPS_PORT  = ordinary chargeable content"

    Invoke-Phase "classifier_naive.py" "naive" `
        "STEP 1+2 - NAIVE CLASSIFIER: legit traffic charged, spoofed traffic waived"

    Invoke-Phase "detector.py" "detector" `
        "STEP 3 - CROSS-VALIDATING DETECTOR: the same spoofed traffic is dropped"

    Write-Banner "SUMMARY"
    & $PY demo_report.py

    Write-Host ""
    Write-Host "  Responsible use: this lab is for validating defensive detection logic on"
    Write-Host "  equipment you own. Do not run the attacker harness against any network"
    Write-Host "  you do not control. See the README for how to report real-world abuse."
    Write-Host ""
}
finally {
    Stop-LabProcesses
}
