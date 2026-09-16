$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
Set-Location frontend
npm install
npm run build
Set-Location ..
if (Test-Path "web/react-dist") { Remove-Item "web/react-dist" -Recurse -Force }
New-Item -ItemType Directory -Path "web/react-dist" | Out-Null
Copy-Item "frontend/dist/*" "web/react-dist/" -Recurse -Force
Write-Host "React production assets copied to web/react-dist/"
