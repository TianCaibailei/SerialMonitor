# Serial tool B: opens COM7, sends frames into the COM6 side.
$ErrorActionPreference = 'Stop'
try {
    $p = New-Object System.IO.Ports.SerialPort('COM7', 9600)
    $p.Open()
    for ($i = 0; $i -lt 6; $i++) {
        $p.Write("TOOL-B-FRAME$i;")
        Start-Sleep -Milliseconds 400
        $null = $p.ReadExisting()
    }
    Start-Sleep -Milliseconds 2000
    $p.Close()
} catch {
    Set-Content -Path (Join-Path $env:TEMP 'tool-b-error.txt') -Value $_.Exception.Message
}
