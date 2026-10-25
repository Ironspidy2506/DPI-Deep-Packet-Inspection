using System.Collections.Concurrent;
using System.Net;

namespace PacketAnalyzer;

public enum PacketAction { Forward, Drop }

public enum AppType
{
    Unknown, Google, YouTube, Facebook, Instagram, Twitter, Netflix, Amazon,
    Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub
}

public sealed class EngineConfig
{
    public int LoadBalancers { get; set; } = 2;
    public int WorkersPerBalancer { get; set; } = 2;
    public int QueueCapacity { get; set; } = 10_000;
    public bool Verbose { get; set; }
    public string? RulesFile { get; set; }
}

public sealed class PcapGlobalHeader
{
    public uint Magic { get; set; } = 0xa1b2c3d4;
    public ushort VersionMajor { get; set; } = 2;
    public ushort VersionMinor { get; set; } = 4;
    public int ThisZone { get; set; }
    public uint SigFigs { get; set; }
    public uint SnapLen { get; set; } = 65535;
    public uint Network { get; set; } = 1;
    public bool LittleEndian { get; set; } = true;
}

public sealed record PcapPacketHeader(uint TsSec, uint TsUsec, uint InclLen, uint OrigLen);
public sealed record RawPacket(PcapPacketHeader Header, byte[] Data);

public sealed class ParsedPacket
{
    public string SrcMac { get; set; } = "";
    public string DstMac { get; set; } = "";
    public string SrcIp { get; set; } = "";
    public string DstIp { get; set; } = "";
    public ushort SrcPort { get; set; }
    public ushort DstPort { get; set; }
    public byte Protocol { get; set; }
    public byte TcpFlags { get; set; }
    public int IpOffset { get; set; }
    public int TransportOffset { get; set; }
    public int PayloadOffset { get; set; }
    public int PayloadLength { get; set; }
    public bool HasIp { get; set; }
    public bool HasTcp { get; set; }
    public bool HasUdp { get; set; }
    public string? Domain { get; set; }
    public AppType Application { get; set; } = AppType.Unknown;
}

public readonly record struct FiveTuple(string SrcIp, string DstIp, ushort SrcPort, ushort DstPort, byte Protocol)
{
    public override string ToString() => $"{SrcIp}:{SrcPort} -> {DstIp}:{DstPort} ({Protocol})";
}

public sealed class PacketJob
{
    public uint PacketId { get; init; }
    public uint TsSec { get; init; }
    public uint TsUsec { get; init; }
    public required FiveTuple Tuple { get; init; }
    public required byte[] Data { get; init; }
    public byte TcpFlags { get; init; }
    public int PayloadOffset { get; init; }
    public int PayloadLength { get; init; }
    public string? Domain { get; init; }
    public AppType Application { get; init; }
}

public sealed class DPIStats
{
    public long TotalPackets;
    public long TotalBytes;
    public long TcpPackets;
    public long UdpPackets;
    public long ForwardedPackets;
    public long DroppedPackets;
    public long ParseErrors;
    public long ClassifiedPackets;
}

public sealed class WorkerStats
{
    public long Processed;
    public long Forwarded;
    public long Dropped;
}

public static class AppClassifier
{
    private static readonly (string Marker, AppType App)[] Domains =
    {
        ("youtube.com", AppType.YouTube), ("googlevideo.com", AppType.YouTube),
        ("google.com", AppType.Google), ("googleapis.com", AppType.Google),
        ("facebook.com", AppType.Facebook), ("fbcdn.net", AppType.Facebook),
        ("instagram.com", AppType.Instagram), ("twitter.com", AppType.Twitter),
        ("x.com", AppType.Twitter), ("netflix.com", AppType.Netflix),
        ("nflxvideo.net", AppType.Netflix), ("amazon.com", AppType.Amazon),
        ("amazonaws.com", AppType.Amazon), ("microsoft.com", AppType.Microsoft),
        ("live.com", AppType.Microsoft), ("apple.com", AppType.Apple),
        ("icloud.com", AppType.Apple), ("whatsapp.com", AppType.WhatsApp),
        ("telegram.org", AppType.Telegram), ("tiktok.com", AppType.TikTok),
        ("tiktokcdn.com", AppType.TikTok), ("spotify.com", AppType.Spotify),
        ("zoom.us", AppType.Zoom), ("discord.com", AppType.Discord),
        ("github.com", AppType.GitHub)
    };

    public static AppType FromDomain(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return AppType.Unknown;
        string d = domain.Trim().TrimEnd('.').ToLowerInvariant();
        foreach (var (marker, app) in Domains)
            if (d == marker || d.EndsWith("." + marker, StringComparison.Ordinal))
                return app;
        return AppType.Unknown;
    }
}
