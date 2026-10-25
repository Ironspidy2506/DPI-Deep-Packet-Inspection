$ErrorActionPreference = "Stop"
$project = Join-Path $PSScriptRoot "..\PacketAnalyzer.csproj"
dotnet restore $project
dotnet build $project --configuration Release
