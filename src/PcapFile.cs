using System.Buffers.Binary;

namespace PacketAnalyzer;

public sealed class PcapReader : IDisposable
{
    private readonly FileStream _stream;
    private readonly BinaryReader _reader;
    public PcapGlobalHeader GlobalHeader { get; }
    private readonly bool _littleEndian;

    public PcapReader(string path)
    {
        _stream = File.OpenRead(path);
        _reader = new BinaryReader(_stream);
        byte[] h = _reader.ReadBytes(24);
        if (h.Length != 24) throw new InvalidDataException("PCAP global header is truncated.");

        uint rawMagic = BinaryPrimitives.ReadUInt32LittleEndian(h.AsSpan(0, 4));
        _littleEndian = rawMagic switch
        {
            0xa1b2c3d4 => true,
            0xd4c3b2a1 => false,
            0xa1b23c4d => true,
            0x4d3cb2a1 => false,
            _ => throw new InvalidDataException($"Unsupported PCAP magic number: 0x{rawMagic:X8}")
        };

        bool nano = rawMagic is 0xa1b23c4d or 0x4d3cb2a1;
        GlobalHeader = new PcapGlobalHeader
        {
            Magic = rawMagic,
            VersionMajor = U16(h, 4),
            VersionMinor = U16(h, 6),
            ThisZone = unchecked((int)U32(h, 8)),
            SigFigs = U32(h, 12),
            SnapLen = U32(h, 16),
            Network = U32(h, 20),
            LittleEndian = _littleEndian,
            // The timestamp unit is retained separately by this reader.
        };
        IsNanosecondResolution = nano;
        if (GlobalHeader.Network != 1)
            throw new InvalidDataException($"This parser supports Ethernet PCAP only (link type 1); file uses {GlobalHeader.Network}.");
        Console.WriteLine($"Opened PCAP: {path} ({GlobalHeader.VersionMajor}.{GlobalHeader.VersionMinor}, snaplen {GlobalHeader.SnapLen})");
    }

    public bool IsNanosecondResolution { get; }

    private ushort U16(byte[] b, int o) => _littleEndian
        ? BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(o, 2))
        : BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(o, 2));
    private uint U32(byte[] b, int o) => _littleEndian
        ? BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o, 4))
        : BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(o, 4));

    public bool TryRead(out RawPacket? packet)
    {
        packet = null;
        if (_stream.Position == _stream.Length) return false;
        byte[] ph = _reader.ReadBytes(16);
        if (ph.Length == 0) return false;
        if (ph.Length != 16) throw new InvalidDataException("Truncated PCAP packet header.");

        uint tsSec = U32(ph, 0), tsFrac = U32(ph, 4), incl = U32(ph, 8), orig = U32(ph, 12);
        if (incl > GlobalHeader.SnapLen || incl > 16 * 1024 * 1024)
            throw new InvalidDataException($"Invalid packet length {incl}.");
        byte[] data = _reader.ReadBytes(checked((int)incl));
        if (data.Length != incl) throw new InvalidDataException("Truncated packet payload.");
        // Normalize nanosecond timestamps to microseconds for the writer.
        if (IsNanosecondResolution) tsFrac /= 1000;
        packet = new RawPacket(new PcapPacketHeader(tsSec, tsFrac, incl, orig), data);
        return true;
    }

    public void Dispose() { _reader.Dispose(); _stream.Dispose(); }
}

public sealed class PcapWriter : IDisposable
{
    private readonly FileStream _stream;
    private readonly BinaryWriter _writer;
    private readonly bool _littleEndian;

    public PcapWriter(string path, PcapGlobalHeader sourceHeader)
    {
        _stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read);
        _writer = new BinaryWriter(_stream);
        _littleEndian = sourceHeader.LittleEndian;
        WriteU32(0xa1b2c3d4);
        WriteU16(sourceHeader.VersionMajor);
        WriteU16(sourceHeader.VersionMinor);
        WriteU32(unchecked((uint)sourceHeader.ThisZone));
        WriteU32(sourceHeader.SigFigs);
        WriteU32(sourceHeader.SnapLen);
        WriteU32(sourceHeader.Network);
    }

    private void WriteU16(ushort value)
    {
        Span<byte> b = stackalloc byte[2];
        if (_littleEndian) BinaryPrimitives.WriteUInt16LittleEndian(b, value);
        else BinaryPrimitives.WriteUInt16BigEndian(b, value);
        _writer.Write(b);
    }
    private void WriteU32(uint value)
    {
        Span<byte> b = stackalloc byte[4];
        if (_littleEndian) BinaryPrimitives.WriteUInt32LittleEndian(b, value);
        else BinaryPrimitives.WriteUInt32BigEndian(b, value);
        _writer.Write(b);
    }

    public void Write(RawPacket packet)
    {
        WriteU32(packet.Header.TsSec);
        WriteU32(packet.Header.TsUsec);
        WriteU32((uint)packet.Data.Length);
        WriteU32(packet.Header.OrigLen);
        _writer.Write(packet.Data);
    }

    public void Flush() => _writer.Flush();
    public void Dispose() { _writer.Flush(); _writer.Dispose(); _stream.Dispose(); }
}
