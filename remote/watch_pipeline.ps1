# Observes the detached pipeline on the Mac and reports when it finishes/aborts.
# Tolerant of dropped access: failed SSH polls are skipped and it resumes later.
$ErrorActionPreference = "Continue"
$key = "$env:USERPROFILE\.ssh\cactus_interop"
$h   = "mac@192.168.1.33"
function Rmt($c) { ssh -i $key -o ConnectTimeout=12 $h $c 2>$null }

Write-Output "WATCH_START $(Get-Date -Format 'HH:mm:ss')"
for ($i = 0; $i -lt 720; $i++) {
  $t = ((Rmt "tail -c 400 ~/bbverifier/logs/pipeline.log 2>/dev/null | tr '\r' '\n' | tail -2") -join ' ').Trim()
  if ($t) { Write-Output ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $t) }
  else    { Write-Output ("[{0}] (no access)" -f (Get-Date -Format 'HH:mm:ss')) }
  if ($t -match 'ALL DONE') {
    Write-Output 'PIPELINE_DONE'
    Rmt "cd ~/bbverifier && echo '--- model ---' && ls -lh vibethinker-bbtriage 2>/dev/null && echo '--- tail ---' && tail -30 logs/pipeline.log | tr '\r' '\n'"
    break
  }
  if ($t -match 'ABORT') {
    Write-Output 'PIPELINE_ABORT'
    Rmt "tail -45 ~/bbverifier/logs/pipeline.log | tr '\r' '\n'"
    break
  }
  Start-Sleep -Seconds 60
}
