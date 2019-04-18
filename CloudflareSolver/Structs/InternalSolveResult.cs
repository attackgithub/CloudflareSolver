namespace Cloudflare.Structs
{
    internal struct InternalSolveResult
    {
        public readonly bool Success;
        public readonly string FailReason;

        public InternalSolveResult(bool success, string layer, string failReason)
        {
            Success = success;

            if (!string.IsNullOrEmpty(failReason))
                FailReason = $"Cloudflare [{layer}]: {failReason}";
            else
                FailReason = null;
        }
    }
}
