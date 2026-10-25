using System.Buffers.Binary;
using System.Text;

namespace PacketAnalyzer;

public static class SniExtractor
{
    public static string? Extract(ReadOnlySpan<byte> payload)
    {
        // TLS record header + handshake header must be present.
        if (payload.Length < 9 || payload[0] != 0x16) return null;
        ushort recordVersion = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(1, 2));
        ushort recordLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(3, 2));
        if (recordVersion is < 0x0300 or > 0x0304 ||
            recordLength > payload.Length - 5 || payload[5] != 0x01)
            return null;

        int recordEnd = Math.Min(payload.Length, 5 + recordLength);
        int o = 9; // Record header (5) + handshake header (4).
        if (o + 34 > recordEnd) return null;
        o += 2 + 32; // Client version and random.

        int sessionLength = payload[o++];
        if (o + sessionLength + 2 > recordEnd) return null;
        o += sessionLength;

        int cipherLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(o, 2));
        o += 2;
        if (o + cipherLength + 1 > recordEnd) return null;
        o += cipherLength;

        int compressionLength = payload[o++];
        if (o + compressionLength + 2 > recordEnd) return null;
        o += compressionLength;

        int extLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(o, 2));
        o += 2;
        int extEnd = Math.Min(recordEnd, o + extLength);

        while (o + 4 <= extEnd)
        {
            ushort type = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(o, 2));
            int length = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(o + 2, 2));
            o += 4;
            if (o + length > extEnd) return null;

            if (type == 0 && length >= 5)
            {
                int listLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(o, 2));
                if (listLength >= 3 && payload[o + 2] == 0)
                {
                    int nameLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(o + 3, 2));
                    if (nameLength <= length - 5)
                    {
                        string name = Encoding.ASCII.GetString(payload.Slice(o + 5, nameLength));
                        return string.IsNullOrWhiteSpace(name) ? null : name.TrimEnd('.').ToLowerInvariant();
                    }
                }
            }
            o += length;
        }
        return null;
    }
}
