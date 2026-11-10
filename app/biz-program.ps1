# The "business program": owns a serial port exclusively and keeps communicating.
# Writes the bytes it receives to a result file so the caller can check integrity.
param(
    [string]$Port = 'COM6',
    [int]$Frames = 40,
    [string]$ResultFile = "$env:TEMP\biz-result.txt"
)
$ErrorActionPreference = 'Stop'
$p = New-Object System.IO.Ports.SerialPort($Port, 9600)
try {
    $p.Open()
} catch {
    Set-Content -Path $ResultFile -Value "OPEN-FAILED: $($_.Exception.Message)"
    exit 2
}
$p.WriteLine('BIZ-READY')
$acc = New-Object System.Text.StringBuilder
for ($i = 0; $i -lt $Frames; $i++) {
    $p.Write("TICK$i;")
    Start-Sleep -Milliseconds 200
    [void]$acc.Append($p.ReadExisting())
}
$p.Close()
Set-Content -Path $ResultFile -Value $acc.ToString()
