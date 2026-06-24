# Deploy bb-triage pipeline files to Lambda with LF-normalized shell scripts.
$ErrorActionPreference = "Stop"
$Key = if ($env:LAMBDA_KEY) { $env:LAMBDA_KEY } else { "$env:USERPROFILE\.ssh\id_ed25519" }
$SshHost = if ($env:LAMBDA_HOST) { $env:LAMBDA_HOST } else { "ubuntu@192.222.53.8" }
$Dest = if ($env:LAMBDA_DEST) { $env:LAMBDA_DEST } else { "bbverifier" }
$Root = (Resolve-Path "$PSScriptRoot\..").Path

Write-Host "[deploy] normalize LF ..."
python "$Root\remote\normalize_lf.py"
if ($LASTEXITCODE -ne 0) { throw "normalize_lf failed" }

$RemoteSh = Get-ChildItem "$Root\remote\*.sh" | ForEach-Object { $_.FullName }
Write-Host "[deploy] scp $($RemoteSh.Count) shell scripts + py ..."
scp -i $Key @(
    "$Root\remote\constants.sh",
    "$Root\remote\serve_vibethinker.py",
    "$Root\remote\train_sft.py",
    "$Root\remote\merge_lora.py",
    "$Root\remote\verify_sft_data.py",
    "$Root\remote\pilot_gate.py"
) "${SshHost}:~/${Dest}/remote/"

foreach ($f in $RemoteSh) {
    scp -i $Key $f "${SshHost}:~/${Dest}/remote/"
}

scp -i $Key "$Root\eval\run_eval.py" "${SshHost}:~/${Dest}/eval/run_eval.py"
scp -i $Key "$Root\app\triage.py" "${SshHost}:~/${Dest}/app/triage.py"
scp -i $Key "$Root\data\trace_gen.py" "${SshHost}:~/${Dest}/data/trace_gen.py"

Write-Host "[deploy] remote verify (no CR in scripts) ..."
ssh -i $Key $SshHost "grep -l `$'\r' ~/$Dest/remote/*.sh 2>/dev/null && echo CR_FOUND && exit 1 || echo LF_OK; chmod +x ~/$Dest/remote/*.sh"
Write-Host "[deploy] DONE"
