# C++ → C# migration notes

## Destination runtime

- Target framework: `net10.0`
- External packages: none
- Entry point: `Program.cs`
- Build: `dotnet build -c Release`

## Consolidated file mapping

The C++ repository contains several alternative entry points and overlapping implementations. Rather than mechanically porting each `main*.cpp` into a separate executable, this conversion consolidates the supported CLI and processing path.

| Original C++ source | .NET destination |
|---|---|
| `include/types.h`, `src/types.cpp` | `src/Models.cs` |
| `include/pcap_reader.h`, `src/pcap_reader.cpp` | `src/PcapFile.cs` |
| `include/connection_tracker.h`, `src/connection_tracker.cpp` | `src/ConnectionTracker.cs` |
| `include/load_balancer.h`, `src/load_balancer.cpp` | `src/LoadBalancerRouter.cs` |
| `include/fast_path.h`, `src/fast_path.cpp` | `src/FastPathProcessor.cs` |
| `include/packet_parser.h`, `src/packet_parser.cpp` | `src/PacketParser.cs` |
| `include/sni_extractor.h`, `src/sni_extractor.cpp` | `src/SniExtractor.cs` |
| `include/rule_manager.h`, `src/rule_manager.cpp` | `src/RuleManager.cs` |
| `include/dpi_engine.h`, `src/dpi_engine.cpp`, `src/dpi_mt.cpp` | `src/DPIEngine.cs` |
| `src/main.cpp`, `src/main_dpi.cpp`, `src/main_simple.cpp`, `src/main_working.cpp` | `Program.cs` |
| `generate_test_pcap.py` | `generate_test_pcap.py` (retained as test-data tooling) |
| `README.md`, `WINDOWS_SETUP.md`, `CMakeLists.txt` | Updated `README.md`, this note, `PacketAnalyzer.csproj`, `scripts/` |

The original connection-tracker and fast-path code has been simplified into the current bounded worker pipeline and aggregate statistics. This is a functional modernization, not a line-by-line semantic clone of every experimental/demo path.

## Important behavior differences

- The pipeline uses .NET bounded `Channel<T>` queues and tasks rather than raw C++ threads and custom queue classes.
- Packet bytes remain in managed `byte[]` arrays. Payload is represented by an offset and length, not a raw pointer.
- PCAP headers are serialized field-by-field rather than by writing native structs, avoiding padding/layout assumptions.
- Rule files can be JSON or simple text; saving rules writes JSON.
- The parser intentionally skips unsupported/non-IPv4/non-TCP/UDP packets.
- SNI and HTTP host extraction operate on the payload in an individual packet. TCP reassembly and TLS decryption are not implemented.
- The worker pipeline is intended for offline file processing and does not attach to a live network interface.

## Validation status

The source environment used to prepare this conversion did not have the .NET SDK/compiler installed, so a local `dotnet build` could not be executed here. Build and run on a machine with .NET SDK 8 installed before relying on results. The project has been manually reviewed, but should be treated as needing compile-time and PCAP regression testing.
