#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$SCRIPT_DIR/../PacketAnalyzer.csproj"
if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <input.pcap> <output.pcap> [DPI options...]"
  exit 2
fi
dotnet run --project "$PROJECT" -- "$@"
