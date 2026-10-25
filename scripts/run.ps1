param(
    [Parameter(Mandatory=$true)][string]$InputPcap,
    [Parameter(Mandatory=$true)][string]$OutputPcap,
    [string[]]$DpiArgs = @()
)
$ErrorActionPreference = "Stop"
$project = Join-Path $PSScriptRoot "..\PacketAnalyzer.csproj"
dotnet run --project $project -- $InputPcap $OutputPcap @DpiArgs
exit $LASTEXITCODE
