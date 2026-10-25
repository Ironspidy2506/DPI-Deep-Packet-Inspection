namespace PacketAnalyzer;

/// <summary>
/// Deterministically routes packets with the same five-tuple to the same
/// worker during one process run. The original implementation had explicit
/// load-balancer threads; this version keeps routing separate from workers.
/// </summary>
public static class LoadBalancerRouter
{
    public static int SelectWorker(FiveTuple tuple, int workerCount)
    {
        if (workerCount <= 0) throw new ArgumentOutOfRangeException(nameof(workerCount));
        return (int)((uint)tuple.GetHashCode() % (uint)workerCount);
    }
}
