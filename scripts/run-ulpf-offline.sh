#!/usr/bin/env bash
set -euo pipefail
export ULPF_AGENT_TOKEN=Tnikita1800
export ULPF_ALLOW_UNAUTHENTICATED_AGENT=false
export ULPF_WEB_PORT=5174
export ULPF_DATA_DIR="${ULPF_DATA_DIR:-$(pwd)/data-runtime}"
export ULPF_CONFIG="${ULPF_CONFIG:-$(pwd)/configs/pipeline.yaml}"
python -m ulpf.web
