$ErrorActionPreference='Stop'
$env:ULPF_AGENT_TOKEN = 'Tnikita1800'
$env:ULPF_ALLOW_UNAUTHENTICATED_AGENT = 'false'
$env:ULPF_WEB_PORT = '5173'
$env:ULPF_DATA_DIR = if ($env:ULPF_DATA_DIR) {$env:ULPF_DATA_DIR} else {(Join-Path (Get-Location) 'data-runtime')}
$env:ULPF_CONFIG = if ($env:ULPF_CONFIG) {$env:ULPF_CONFIG} else {(Join-Path (Get-Location) 'configs/pipeline.yaml')}
python -m ulpf.web
