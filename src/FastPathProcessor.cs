namespace PacketAnalyzer;

/// <summary>Applies the rule manager to one already-parsed packet.</summary>
public sealed class FastPathProcessor
{
    private readonly RuleManager _rules;
    public FastPathProcessor(RuleManager rules) => _rules = rules;

    public PacketAction Process(ParsedPacket packet) =>
        _rules.IsBlocked(packet) ? PacketAction.Drop : PacketAction.Forward;
}
