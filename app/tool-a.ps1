# Serial tool A: opens COM6, sends a few frames, reads what comes back.
$ErrorActionPreference = 'Stop'
try {
    $p = New-Object System.IO.Ports.SerialPort('COM6', 9600)
    $p.Open()
    for ($i = 0; $i -lt 6; $i++) {
        $p.Write("TOOL-A-FRAME$i;")
        Start-Sleep -Milliseconds 400
        $null = $p.ReadExisting()
    }
    Start-Sleep -Milliseconds 2000
    $p.Close()
} catch {
    Set-Content -Path (Join-Path $env:TEMP 'tool-a-error.txt') -Value $_.Exception.Message
}
