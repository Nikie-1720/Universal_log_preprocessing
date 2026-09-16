#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cd frontend
npm install
npm run build
cd ..
rm -rf web/react-dist
mkdir -p web/react-dist
cp -R frontend/dist/. web/react-dist/
echo "React production assets copied to web/react-dist/"
echo "For an air-gapped image, update the static serving target or copy these assets to web/."
