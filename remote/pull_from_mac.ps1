<#
  OFFLINE Mac -> Windows model puller.

  Runs entirely on this Windows machine over the hotspot LAN. Needs NO internet
  and no live agent. It:
    1. finds the Mac on the local subnet (or uses -MacIp if you pass one),
    2. SSHes in and diagnoses what the training pipeline actually produced,
    3. pulls, smallest-and-most-valuable first:
         logs + LoRA adapter  ->  fused model (if present)  ->  base-model cache
         (so we end up able to run/fuse the tune fully offline),
    4. writes a clear STATUS to mac_pull\transfer.log.

  USAGE (from bb-triage\ , after BOTH devices are on the hotspot):
      powershell -ExecutionPolicy Bypass -File remote\pull_from_mac.ps1
  or with a known IP (fastest, most reliable):
      powershell -ExecutionPolicy Bypass -File remote\pull_from_mac.ps1 -MacIp 172.20.10.3
#>
param(
  [string]$MacIp = "192.168.1.33",
  [string]$User  = "mac",
  [string]$Key   = "$env:USERPROFILE\.ssh\cactus_interop"
)

$ErrorActionPreference = "Continue"
$proj   = Split-Path -Parent $PSScriptRoot         # bb-triage\
$outDir = Join-Path $proj "mac_pull"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$log = Join-Path $outDir "transfer.log"

function Log($m) {
  $line = "[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m
  $line | Tee-Object -FilePath $log -Append
}

Log "=== pull_from_mac start ==="
if (-not (Test-Path $Key)) { Log "FATAL: ssh key not found at $Key"; exit 1 }

# --- helper: does this host answer SSH as our Mac? -------------------------
function Test-Mac([string]$ip) {
  $probe = ssh -i $Key -o BatchMode=yes -o StrictHostKeyChecking=no `
              -o ConnectTimeout=4 "$User@$ip" `
              "echo VIBE_OK; ls -d ~/bbverifier 2>/dev/null" 2>$null
  return ($probe -match "VIBE_OK")
}

# --- 1) locate the Mac ------------------------------------------------------
$target = ""
if ($MacIp) {
  Log "trying provided IP $MacIp ..."
  if (Test-Mac $MacIp) { $target = $MacIp; Log "OK: Mac answered at $MacIp" }
  else { Log "provided IP did not answer; falling back to scan" }
}
if (-not $target) {
  # derive local /24 subnets from this box's hotspot interface(s)
  $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
         Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
         Select-Object -ExpandProperty IPAddress
  $bases = @($ips | ForEach-Object { ($_ -split '\.')[0..2] -join '.' } | Sort-Object -Unique)
  Log ("scanning subnets for SSH: " + ($bases -join ', '))
  foreach ($b in $bases) {
    foreach ($h in 1..254) {
      $ip = "$b.$h"
      $t = New-Object System.Net.Sockets.TcpClient
      try {
        $ar = $t.BeginConnect($ip, 22, $null, $null)
        if ($ar.AsyncWaitHandle.WaitOne(120) -and $t.Connected) {
          $t.Close()
          Log "port 22 open at $ip - probing..."
          if (Test-Mac $ip) { $target = $ip; Log "OK: Mac found at $ip"; break }
        }
      } catch {} finally { $t.Close() }
    }
    if ($target) { break }
  }
}
if (-not $target) {
  Log "STATUS=NO_MAC  could not find the Mac on the LAN. Is it on the hotspot + Remote Login on?"
  exit 2
}

$remote = "$User@$target"
function Rmt($c) { ssh -i $Key -o StrictHostKeyChecking=no -o ConnectTimeout=8 $remote $c 2>&1 }
function Pull($src, $dst) {
  Log "scp <- $src"
  scp -i $Key -o StrictHostKeyChecking=no -r "${remote}:$src" $dst 2>&1 | Tee-Object -FilePath $log -Append | Out-Null
}

# --- 2) diagnose ------------------------------------------------------------
Log "--- remote diagnosis ---"
$diag = Rmt @'
cd ~/bbverifier 2>/dev/null || exit 9
echo "HOST=$(hostname)"
echo "RUNNING=$(pgrep -fl 'run_pipeline|mlx_lm.lora|hf download' | tr '\n' ';')"
echo "ADAPTER=$([ -f adapters/adapters.safetensors ] && echo 1 || echo 0)"
echo "ADAPTER_CKPTS=$(ls adapters/*adapters.safetensors 2>/dev/null | wc -l | tr -d ' ')"
echo "FUSED=$([ -f vibethinker-bbtriage/config.json ] && echo 1 || echo 0)"
echo "FUSED_MB=$(du -sm vibethinker-bbtriage 2>/dev/null | cut -f1)"
echo "BASE_MB=$(du -sm ~/.cache/huggingface/hub/models--WeiboAI--VibeThinker-3B 2>/dev/null | cut -f1)"
echo "--- pipeline.log tail ---"
tail -25 logs/pipeline.log 2>/dev/null | tr '\r' '\n'
'@
$diag | Tee-Object -FilePath $log -Append | Out-Null

$adapter = ($diag -match "ADAPTER=1")
$fused   = ($diag -match "FUSED=1")
$baseMb  = 0
if ($diag -match "BASE_MB=(\d+)") { $baseMb = [int]$Matches[1] }

# --- 3) pull (smallest / most valuable first) -------------------------------
Pull "~/bbverifier/logs"            $outDir            # tiny: logs
Pull "~/bbverifier/lora_config.yaml" $outDir
if ($adapter -or ($diag -match "ADAPTER_CKPTS=[1-9]")) {
  Pull "~/bbverifier/adapters" $outDir                # the irreplaceable fine-tune
} else {
  Log "no adapter on the Mac yet"
}
if ($fused) {
  Pull "~/bbverifier/vibethinker-bbtriage" $outDir    # complete standalone model (~6 GB)
} elseif ($adapter -and $baseMb -gt 5000) {
  Log "no fused model, but base cache present ($baseMb MB) -> pulling base so we can fuse offline"
  $cacheDst = Join-Path $outDir "hf_cache_VibeThinker-3B"
  New-Item -ItemType Directory -Force -Path $cacheDst | Out-Null
  Pull "~/.cache/huggingface/hub/models--WeiboAI--VibeThinker-3B" $cacheDst
} else {
  Log "no fused model and no usable base cache to pull"
}

# --- 4) summarize -----------------------------------------------------------
$pulledAdapter = Test-Path (Join-Path $outDir "adapters\adapters.safetensors")
$pulledFused   = Test-Path (Join-Path $outDir "vibethinker-bbtriage\config.json")
Log "----------------------------------------"
Log ("RESULT adapter_local={0} fused_local={1}" -f $pulledAdapter, $pulledFused)
if ($pulledFused)        { Log "STATUS=OK_FUSED  full tuned model is now local in mac_pull\vibethinker-bbtriage" }
elseif ($pulledAdapter)  { Log "STATUS=OK_ADAPTER  adapter is local; base may need re-download/fuse" }
else                     { Log "STATUS=NO_MODEL  training had not produced an adapter yet (see pipeline.log tail above)" }
Log "=== pull_from_mac done ==="
Get-ChildItem -Recurse $outDir -ErrorAction SilentlyContinue |
  Measure-Object -Property Length -Sum | ForEach-Object { Log ("total pulled: {0:N1} MB" -f ($_.Sum/1MB)) }
