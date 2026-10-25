using System.Collections.Concurrent;

namespace PacketAnalyzer;

/// <summary>Thread-safe per-five-tuple counters for flows observed in a PCAP.</summary>
public sealed class ConnectionTracker
{
    private sealed class FlowState
    {
        public long Packets;
        public long Bytes;
        public long LastTimestampMicroseconds;
    }

    private readonly ConcurrentDictionary<FiveTuple, FlowState> _flows = new();

    public void Observe(FiveTuple tuple, int byteCount, uint seconds, uint microseconds)
    {
        var state = _flows.GetOrAdd(tuple, _ => new FlowState());
        Interlocked.Increment(ref state.Packets);
        Interlocked.Add(ref state.Bytes, byteCount);
        Interlocked.Exchange(ref state.LastTimestampMicroseconds,
            (long)seconds * 1_000_000L + microseconds);
    }

    public int FlowCount => _flows.Count;

    public IEnumerable<(FiveTuple Tuple, long Packets, long Bytes, long LastTimestampMicroseconds)> Snapshot() =>
        _flows.Select(pair => (
            pair.Key,
            Interlocked.Read(ref pair.Value.Packets),
            Interlocked.Read(ref pair.Value.Bytes),
            Interlocked.Read(ref pair.Value.LastTimestampMicroseconds)));
}
