# DPI Engine — C# / .NET 10

A .NET 10 rewrite of the original C++ Deep Packet Inspection (DPI) PCAP analyzer. It reads an Ethernet PCAP file, parses IPv4/TCP/UDP packets, extracts plaintext HTTP Host and TLS ClientHello SNI where available, classifies recognized domains, applies blocking rules, writes allowed packets to a new PCAP, and prints statistics.

> **Scope and security note:** this is an offline PCAP analyzer/filter, not a live network firewall. It does not capture packets from a network interface, decrypt TLS, reassemble TCP streams, or inspect encrypted ClientHello (ECH). It currently supports Ethernet + IPv4 + TCP/UDP. Unsupported packets are skipped and counted as parse errors. Validate output before using it for operational security decisions.

## Why C# / .NET?

The rewrite uses modern .NET, `Channel<T>` bounded queues, `Task`, `Interlocked`, and managed byte arrays. These are practical industry skills for backend and systems-oriented .NET roles. The processing pipeline is split into files with no third-party NuGet dependencies.

## Requirements

- .NET 10 SDK
- Windows, Linux, or macOS
- Optional: Python 3.9+ to regenerate the test PCAP

Check your installation:

```bash
dotnet --info
```

Install the .NET 8 SDK from the official .NET download page if `dotnet` is not recognized:
https://dotnet.microsoft.com/download/dotnet/10.0

## Build

From this folder:

### Windows PowerShell

```powershell
.\scripts\build.ps1
```

Or:

```powershell
dotnet restore .\PacketAnalyzer.csproj
dotnet build .\PacketAnalyzer.csproj -c Release
```

### Linux / macOS

```bash
chmod +x ./scripts/build.sh ./scripts/run.sh
./scripts/build.sh
```

Or:

```bash
dotnet restore ./PacketAnalyzer.csproj
dotnet build ./PacketAnalyzer.csproj --configuration Release
```

## Run

Arguments go after `--` when using `dotnet run`.

```bash
dotnet run -- test_dpi.pcap filtered.pcap
```

Release build:

```bash
dotnet run -c Release -- test_dpi.pcap filtered.pcap
```

Block traffic involving an IP address:

```bash
dotnet run -- test_dpi.pcap filtered.pcap --block-ip 192.168.1.100
```

Block an application identified from a visible domain:

```bash
dotnet run -- test_dpi.pcap filtered.pcap --block-app YouTube
```

Block a domain or wildcard subdomains:

```bash
dotnet run -- test_dpi.pcap filtered.pcap --block-domain "*.tiktok.com"
```

Load a rules file:

```bash
dotnet run -- test_dpi.pcap filtered.pcap --rules rules.example.json
```

Tune concurrency and queue capacity:

```bash
dotnet run -- test_dpi.pcap filtered.pcap --lbs 2 --fps 4 --queue-size 10000 --verbose
```

Save active rules:

```bash
dotnet run -- test_dpi.pcap filtered.pcap --block-app YouTube --save-rules rules.saved.json
```

The `--lbs` and `--fps` options set the number of logical partitions and worker tasks. Total worker count is `lbs × fps`.

### Convenience scripts

PowerShell:

```powershell
.\scripts\run.ps1 -InputPcap .\test_dpi.pcap -OutputPcap .\filtered.pcap -DpiArgs @("--block-app", "YouTube")
```

Linux / macOS:

```bash
./scripts/run.sh test_dpi.pcap filtered.pcap --block-app YouTube
```

## Rule formats

### JSON

Use `rules.example.json` as a starting point:

```json
{
  "blockIps": ["192.168.1.50"],
  "blockApps": ["YouTube", "TikTok"],
  "blockDomains": ["example.org", "*.tiktok.com"]
}
```

### Text

A plain-text file can contain one rule per line. Empty lines and lines starting with `#` are ignored:

```text
block-ip 192.168.1.50
block-app YouTube
block-domain *.tiktok.com
block-domain example.org
```

Supported application names include Google, YouTube, Facebook, Instagram, Twitter, Netflix, Amazon, Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, and GitHub. Application detection is heuristic and depends on a domain being visible in the packet payload.

## Project layout

```text
Packet_analyzer_dotnet/
├── PacketAnalyzer.csproj
├── Program.cs                 # CLI and argument parsing
├── rules.example.json
├── test_dpi.pcap               # Sample input PCAP
├── generate_test_pcap.py       # Optional test-PCAP generator
├── src/
│   ├── Models.cs               # Packet models, config, statistics, classifier
│   ├── PcapFile.cs             # Endian-aware PCAP reader/writer
│   ├── PacketParser.cs         # Ethernet/VLAN, IPv4, TCP/UDP parsing
│   ├── SniExtractor.cs         # TLS ClientHello SNI extraction
│   ├── RuleManager.cs          # IP, application, and domain rules
│   └── DPIEngine.cs            # Bounded worker pipeline and reporting
└── scripts/
    ├── build.ps1
    ├── build.sh
    ├── run.ps1
    └── run.sh
```

The C++ repository had several alternative/demo entry points. They have been consolidated into one supported .NET CLI rather than maintaining multiple competing `main` programs.

## What the implementation does

1. Reads the PCAP global header and packet records, respecting the input file's byte order.
2. Parses Ethernet frames (including one VLAN tag), IPv4, TCP, and UDP headers with bounds checks.
3. Attempts to read TLS SNI from a ClientHello or HTTP `Host` from an unencrypted request.
4. Classifies recognized domains into a best-effort application category.
5. Dispatches packets to bounded worker channels based on their five-tuple hash, keeping packets from the same flow on the same worker within a process.
6. Tracks observed flows and applies IP, domain, wildcard-domain, and application rules through the fast-path component.
7. Writes forwarded packets to a new PCAP and prints packet/drop/classification/flow statistics.

## Limitations to understand

- **No TCP stream reassembly:** TLS ClientHello or HTTP headers split across packets may not be detected.
- **No TLS decryption:** modern HTTPS payloads are encrypted; SNI may be unavailable due to Encrypted ClientHello (ECH) or packet truncation.
- **IPv4 only:** IPv6 and non-Ethernet link types are not parsed.
- **No fragment reassembly:** fragmented IP packets may not be classifiable.
- **Offline processing only:** the app does not attach to a network adapter or alter live traffic.
- **Hash-based scheduling:** worker selection is designed for flow affinity, but .NET hash values should not be used as stable identifiers between separate runs.
- **Testing:** the original repository's C++ binary and output PCAP are not used by this .NET project. Build and run with the SDK installed, then compare results against known test captures before relying on it.

## Regenerate the sample PCAP

```bash
python generate_test_pcap.py
```

The script writes `test_dpi.pcap` into the current working directory. This overwrites the existing file with a newly generated sample.

## Troubleshooting

- `dotnet: command not found` / “dotnet is not recognized”: install the .NET 10 SDK.
- `Input PCAP does not exist`: check the input path relative to the current working directory.
- `supports Ethernet PCAP only`: use a capture with link type Ethernet (DLT_EN10MB).
- Output contains fewer packets than input: unsupported or malformed packets are skipped, and packets matching a blocking rule are intentionally dropped.
- No application classification: traffic may be encrypted, truncated, fragmented, split across TCP segments, or use an unrecognized domain.

## License and provenance

This folder is a language/runtime conversion of the provided project, reorganized into a single .NET CLI. Review the original repository's license before redistributing the project.
