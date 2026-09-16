#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist/ULPF-Agent-Plugin"
ZIP="$ROOT/dist/ULPF-Agent-Plugin.zip"
rm -rf "$OUT" "$ZIP"
mkdir -p "$OUT"
cp -R "$ROOT/agent" "$OUT/agent"
cp "$ROOT/scripts/install-ulpf-agent-linux.sh" "$OUT/Install-Agent-Linux.sh"
cp "$ROOT/installer/plugin-manifest.json" "$OUT/plugin-manifest.json"
cp "$ROOT/installer/README.md" "$OUT/README.md"
chmod +x "$OUT/Install-Agent-Linux.sh"
(cd "$ROOT/dist" && zip -qr "$(basename "$ZIP")" "$(basename "$OUT")")
echo "Plugin bundle created: $ZIP"
