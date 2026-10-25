using System.Buffers.Binary;
using System.Text;

namespace PacketAnalyzer;

public static class PacketParser
{
    public static bool TryParse(RawPacket raw, out ParsedPacket p)
    {
        p = new ParsedPacket();
        ReadOnlySpan<byte> d = raw.Data;
        if (d.Length < 14) return false;

        p.DstMac = Mac(d[..6]);
        p.SrcMac = Mac(d.Slice(6, 6));
        ushort etherType = BinaryPrimitives.ReadUInt16BigEndian(d.Slice(12, 2));
        int off = 14;

        // Support one 802.1Q VLAN tag.
        if (etherType is 0x8100 or 0x88A8)
        {
            if (d.Length < 18) return false;
            etherType = BinaryPrimitives.ReadUInt16BigEndian(d.Slice(16, 2));
            off = 18;
        }
        if (etherType != 0x0800) return false; // IPv4 only in this implementation.
        if (d.Length < off + 20) return false;

        byte verIhl = d[off];
        int ihl = (verIhl & 0x0f) * 4;
        if ((verIhl >> 4) != 4 || ihl < 20 || d.Length < off + ihl) return false;
        ushort totalLen = BinaryPrimitives.ReadUInt16BigEndian(d.Slice(off + 2, 2));
        if (totalLen < ihl || d.Length < off + ihl) return false;

        p.HasIp = true;
        p.IpOffset = off;
        p.SrcIp = new System.Net.IPAddress(d.Slice(off + 12, 4)).ToString();
        p.DstIp = new System.Net.IPAddress(d.Slice(off + 16, 4)).ToString();
        p.Protocol = d[off + 9];
        int ipEnd = Math.Min(d.Length, off + totalLen);
        int transport = off + ihl;
        p.TransportOffset = transport;

        if (p.Protocol == 6)
        {
            if (ipEnd < transport + 20) return false;
            p.SrcPort = BinaryPrimitives.ReadUInt16BigEndian(d.Slice(transport, 2));
            p.DstPort = BinaryPrimitives.ReadUInt16BigEndian(d.Slice(transport + 2, 2));
            int tcpLen = ((d[transport + 12] >> 4) & 0x0f) * 4;
            if (tcpLen < 20 || ipEnd < transport + tcpLen) return false;
            p.TcpFlags = d[transport + 13];
            p.HasTcp = true;
            p.PayloadOffset = transport + tcpLen;
        }
        else if (p.Protocol == 17)
        {
            if (ipEnd < transport + 8) return false;
            p.SrcPort = BinaryPrimitives.ReadUInt16BigEndian(d.Slice(transport, 2));
            p.DstPort = BinaryPrimitives.ReadUInt16BigEndian(d.Slice(transport + 2, 2));
            p.HasUdp = true;
            p.PayloadOffset = transport + 8;
        }
        else return false;

        p.PayloadLength = Math.Max(0, ipEnd - p.PayloadOffset);
        if (p.PayloadLength > 0)
        {
            ReadOnlySpan<byte> payload = d.Slice(p.PayloadOffset, p.PayloadLength);
            p.Domain = SniExtractor.Extract(payload) ?? ExtractHttpHost(payload);
            p.Application = AppClassifier.FromDomain(p.Domain);
        }
        return true;
    }

    private static string Mac(ReadOnlySpan<byte> b) => string.Join(":", b.ToArray().Select(x => x.ToString("x2")));

    private static string? ExtractHttpHost(ReadOnlySpan<byte> payload)
    {
        int n = Math.Min(payload.Length, 8192);
        string text = Encoding.ASCII.GetString(payload[..n]);
        if (!(text.StartsWith("GET ", StringComparison.OrdinalIgnoreCase) ||
              text.StartsWith("POST ", StringComparison.OrdinalIgnoreCase) ||
              text.StartsWith("PUT ", StringComparison.OrdinalIgnoreCase) ||
              text.StartsWith("HEAD ", StringComparison.OrdinalIgnoreCase) ||
              text.StartsWith("DELETE ", StringComparison.OrdinalIgnoreCase) ||
              text.StartsWith("OPTIONS ", StringComparison.OrdinalIgnoreCase)))
            return null;

        foreach (string line in text.Split("\r\n", StringSplitOptions.None))
        {
            if (line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
                return line[5..].Trim().Split(':')[0].Trim().TrimEnd('.');
        }
        return null;
    }
}
