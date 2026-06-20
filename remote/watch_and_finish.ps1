# Watches the detached LoRA training on the Mac. When the training process exits,
# if a final adapter exists it auto-fuses the standalone model and runs the smoke
# test. Backgrounded from Windows; emits a final status when everything is done.
$ErrorActionPreference = "Continue"
$key = "$env:USERPROFILE\.ssh\cactus_interop"
$h   = "mac@192.168.1.33"
function Rmt($c) { ssh -i $key -o ConnectTimeout=15 $h $c }

Write-Output "WATCH_START $(Get-Date -Format 'HH:mm:ss')"
for ($i = 0; $i -lt 480; $i++) {
  $alive = (Rmt "pgrep -f mlx_lm.lora >/dev/null && echo RUN || echo STOP").Trim()
  $tail  = ((Rmt "tail -c 300 ~/bbverifier/logs/train.log | tr '\r' '\n' | tail -2") -join ' ').Trim()
  Write-Output ("[{0}] {1} :: {2}" -f (Get-Date -Format HH:mm:ss), $alive, $tail)
  if ($alive -eq 'STOP') { break }
  if ($tail -match 'Traceback|RuntimeError|out of memory') { Write-Output 'CRASH_DETECTED'; break }
  Start-Sleep -Seconds 120
}

$hasAdapter = (Rmt "test -f ~/bbverifier/adapters/adapters.safetensors && echo YES || echo NO").Trim()
Write-Output "TRAINING_STOPPED  ADAPTER=$hasAdapter  $(Get-Date -Format 'HH:mm:ss')"

if ($hasAdapter -eq 'YES') {
  Write-Output "=== FUSING STANDALONE MODEL ==="
  ((Get-Content "$PSScriptRoot\fuse.sh" -Raw) -replace "`r`n", "`n") | ssh -i $key $h "bash -s"
  Write-Output "=== SMOKE TEST (tuned model) ==="
  Rmt "cd ~/bbverifier && .venv/bin/python smoke.py vibethinker-bbtriage 8"
  Write-Output "=== PIPELINE COMPLETE: ~/bbverifier/vibethinker-bbtriage ==="
} else {
  Write-Output "=== NO FINAL ADAPTER - last 40 log lines ==="
  Rmt "tail -40 ~/bbverifier/logs/train.log | tr '\r' '\n'"
}
