param(
    [string]$InstallDir = "C:\Program Files\ULPF-Agent",
    [string]$DataDir = "C:\ProgramData\ULPF-Agent",
    [string]$ServiceName = "ULPFAgent",
    [string]$Gateway = "http://127.0.0.1:5173",
    [switch]$NoService
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) {
    Write-Host "[ULPF] $Message" -ForegroundColor Cyan
}

function Find-Python {
    $commands = @("py", "python", "python3")

    foreach ($cmd in $commands) {
        try {
            $result = & $cmd -3 -c "import sys; print(sys.executable); print(sys.version_info.major); print(sys.version_info.minor)" 2>$null

            if ($LASTEXITCODE -eq 0 -and $result.Count -ge 3) {
                $exe = $result[0].Trim()
                $major = [int]$result[1]
                $minor = [int]$result[2]

                if (($major -gt 3) -or ($major -eq 3 -and $minor -ge 9)) {
                    return $exe
                }
            }
        }
        catch {
        }

        try {
            $result = & $cmd -c "import sys; print(sys.executable); print(sys.version_info.major); print(sys.version_info.minor)" 2>$null

            if ($LASTEXITCODE -eq 0 -and $result.Count -ge 3) {
                $exe = $result[0].Trim()
                $major = [int]$result[1]
                $minor = [int]$result[2]

                if (($major -gt 3) -or ($major -eq 3 -and $minor -ge 9)) {
                    return $exe
                }
            }
        }
        catch {
        }
    }

    return $null
}

Write-Host ""
Write-Host "===============================================" -ForegroundColor Green
Write-Host "          ULPF AGENT PLUGIN INSTALLER" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Green
Write-Host ""

Write-Step "Detecting operating system..."

if ($env:OS -ne "Windows_NT") {
    throw "This installer is for Windows only."
}

$os = Get-CimInstance Win32_OperatingSystem

Write-Host "  OS           : $($os.Caption)"
Write-Host "  Architecture : $env:PROCESSOR_ARCHITECTURE"
Write-Host "  Hostname     : $env:COMPUTERNAME"

Write-Step "Checking runtime..."

$pythonExe = Find-Python

if (-not $pythonExe) {
    throw "Python 3.9+ was not found."
}

Write-Host "  Python       : $pythonExe"

# ROOT PROJECT STRUCTURE:
# project\
#   agent\
#   scripts\
# Therefore scripts\..\agent is correct.
$sourceAgent = Join-Path $PSScriptRoot "agent"

$sourceAgent = [System.IO.Path]::GetFullPath($sourceAgent)

if (-not (Test-Path (Join-Path $sourceAgent "agent.py"))) {
    throw "Agent source not found: $sourceAgent"
}

Write-Host "  Source       : $sourceAgent"

Write-Step "Creating installation directories..."

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

$stateDir = Join-Path $DataDir "state"

New-Item -ItemType Directory -Force -Path $stateDir | Out-Null

Write-Step "Installing ULPF Agent files..."

$targetAgent = Join-Path $InstallDir "agent"

if (Test-Path $targetAgent) {
    Remove-Item $targetAgent -Recurse -Force
}

Copy-Item `
    -Path $sourceAgent `
    -Destination $InstallDir `
    -Recurse `
    -Force

$agentPath = Join-Path $targetAgent "agent.py"

if (-not (Test-Path $agentPath)) {
    throw "Installed agent.py not found: $agentPath"
}

$configPath = Join-Path $DataDir "agent.yaml"
$spoolPath = Join-Path $stateDir "spool.db"
$offsetPath = Join-Path $stateDir "offsets.json"
$agentIdPath = Join-Path $stateDir "agent-id"

$config = @"
# ULPF Agent configuration

gateway: "$Gateway"
token: "Tnikita1800"
name: ""

agent_id_file: "$($agentIdPath.Replace('\','/'))"
spool: "$($spoolPath.Replace('\','/'))"
offset_file: "$($offsetPath.Replace('\','/'))"

windows_eventlog: true

windows_channels:
  - "System"
  - "Application"
  - "Security"
  - "Microsoft-Windows-PowerShell/Operational"

files: []
directories: []
journald: false

poll_interval: 2
windows_poll_interval: 5
send_interval: 0.5
batch_size: 100
heartbeat_interval: 10
"@

Set-Content `
    -Path $configPath `
    -Value $config `
    -Encoding UTF8

Write-Host "  Agent        : $agentPath"
Write-Host "  Config       : $configPath"

$manifest = @{
    product = "ULPF Agent"
    version = "1.0.0"
    service_name = $ServiceName
    install_dir = $InstallDir
    data_dir = $DataDir
    config = $configPath
    installed_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    os = $os.Caption
    architecture = $env:PROCESSOR_ARCHITECTURE
} | ConvertTo-Json -Depth 5

Set-Content `
    -Path (Join-Path $DataDir "install-manifest.json") `
    -Value $manifest `
    -Encoding UTF8

if ($NoService) {

    Write-Host ""
    Write-Host "Service installation skipped." -ForegroundColor Yellow

}
else {

    Write-Step "Registering Windows service..."

    Write-Host "  Service      : $ServiceName"

    # Stop/delete old service if it exists.
    $existing = Get-Service `
        -Name $ServiceName `
        -ErrorAction SilentlyContinue

    if ($existing) {

        Write-Host "  Existing service found."

        if ($existing.Status -eq "Running") {
            Write-Host "  Stopping existing service..."
            & sc.exe stop $ServiceName | Out-Null
            Start-Sleep -Seconds 2
        }

        Write-Host "  Removing existing service..."
        & sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 2
    }

    # IMPORTANT:
    # Use New-Service instead of sc.exe create.
    # This avoids PowerShell/sc.exe argument parsing problems.

    Write-Host "  Creating Windows service..."

    $serviceBinary = "`"$pythonExe`" `"$agentPath`" --config `"$configPath`""

    try {

        New-Service `
            -Name $ServiceName `
            -BinaryPathName $serviceBinary `
            -DisplayName "ULPF Collector Agent" `
            -Description "ULPF local telemetry collector and registration agent" `
            -StartupType Automatic `
            -ErrorAction Stop | Out-Null

    }
    catch {

        Write-Host ""
        Write-Host "ERROR: Windows service creation failed." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-Host ""

        throw
    }

    Write-Host "  Service created successfully." -ForegroundColor Green

    # Configure recovery using sc.exe.
    Write-Host "  Configuring service recovery..."

    & sc.exe failure $ServiceName `
        "reset= 86400" `
        "actions= restart/5000/restart/10000/restart/30000" `
        | Out-Null

    # Verify service.
    $service = Get-Service `
        -Name $ServiceName `
        -ErrorAction SilentlyContinue

    if (-not $service) {
        throw "Service registration verification failed."
    }

    Write-Host "  Service registered successfully." -ForegroundColor Green

    Write-Host "  Starting service..."

    try {

        Start-Service `
            -Name $ServiceName `
            -ErrorAction Stop

    }
    catch {

        Write-Host ""
        Write-Host "ERROR: Windows service could not be started." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-Host ""

        Write-Host "Service configuration:" -ForegroundColor Yellow

        & sc.exe qc $ServiceName

        throw
    }

    Start-Sleep -Seconds 3

    $service = Get-Service `
        -Name $ServiceName `
        -ErrorAction SilentlyContinue

    if (-not $service) {
        throw "Service disappeared after startup."
    }

    Write-Host ""
    Write-Host "  Service      : $ServiceName" -ForegroundColor Green
    Write-Host "  Status       : $($service.Status)" -ForegroundColor Green

    if ($service.Status -ne "Running") {

        Write-Host ""
        Write-Host "WARNING: Service exists but is not running." -ForegroundColor Yellow

        Write-Host ""
        Write-Host "Service configuration:" -ForegroundColor Yellow

        & sc.exe qc $ServiceName
    }
}

Write-Host ""
Write-Host "===============================================" -ForegroundColor Green
Write-Host "     ULPF AGENT INSTALLATION COMPLETED" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Green
Write-Host ""

Write-Host "Install : $InstallDir"
Write-Host "Data    : $DataDir"
Write-Host "Config  : $configPath"

Write-Host ""

if (-not $NoService) {

    $final = Get-Service `
        -Name $ServiceName `
        -ErrorAction SilentlyContinue

    if ($final -and $final.Status -eq "Running") {

        Write-Host "ULPF Agent service is RUNNING." -ForegroundColor Green

    }
    else {

        Write-Host "ULPF Agent service is NOT RUNNING." -ForegroundColor Yellow

    }
}

Write-Host ""
Write-Host "Next step: run agent discovery:" -ForegroundColor Yellow
Write-Host "python `"$agentPath`" discover --config `"$configPath`"" -ForegroundColor Cyan
Write-Host ""