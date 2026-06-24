# Serve VibeThinker-3B-BugBounty-Triage locally on http://127.0.0.1:8080/v1
# Base: ~/emberglass/model  |  LoRA: mac_pull adapter
$ErrorActionPreference = "Stop"
$Bb = Split-Path $PSScriptRoot -Parent
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
  throw "uv not found — install from https://docs.astral.sh/uv/"
}

$Base = if ($env:BASE_MODEL) { $env:BASE_MODEL } else { Join-Path $env:USERPROFILE "emberglass\model" }
$Adapter = if ($env:ADAPTER_PATH) { $env:ADAPTER_PATH } else {
  Join-Path $Bb "mac_pull\highconf_sanitized_20260623\extracted\adapters\highconf-sanitized-20260623"
}
$Port = if ($env:SERVE_PORT) { $env:SERVE_PORT } else { "8080" }

if (-not (Test-Path (Join-Path $Base "config.json"))) { throw "Base model missing at $Base" }
if (-not (Test-Path (Join-Path $Adapter "adapter_config.json"))) { throw "Adapter missing at $Adapter" }

$env:MODEL_NAME = "VibeThinker-3B-BugBounty-Triage"
$env:SERVE_MODEL_NAME = $env:MODEL_NAME
$env:SERVE_DEVICE = "cpu"

Write-Host "[serve_local] base=$Base"
Write-Host "[serve_local] adapter=$Adapter"
Write-Host "[serve_local] http://127.0.0.1:$Port/v1  model=$($env:MODEL_NAME)"
Write-Host "[serve_local] uv sync --group serve (first run may take a minute)..."

Set-Location $Bb
uv lock
uv sync --group serve
uv run python remote\serve_vibethinker.py --model $Base --adapter $Adapter --host 127.0.0.1 --port $Port
