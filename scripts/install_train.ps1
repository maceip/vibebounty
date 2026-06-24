# Install training CLI via uv (run from vibebounty root).
$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
Push-Location $Root
try {
  if (-not (Get-Command uv -ErrorAction SilentlyContinue)) { throw "uv not found: https://docs.astral.sh/uv/" }
  uv lock
  uv sync
  uv run emberglass-tune --help
} finally {
  Pop-Location
}
