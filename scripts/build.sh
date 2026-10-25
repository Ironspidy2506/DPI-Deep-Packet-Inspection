#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$SCRIPT_DIR/../PacketAnalyzer.csproj"
dotnet restore "$PROJECT"
dotnet build "$PROJECT" --configuration Release
