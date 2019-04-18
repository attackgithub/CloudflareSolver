namespace Cloudflare.Structs
{
    public struct DetectResult
    {
        public CloudflareProtection Protection;
        public string Html;

        public override string ToString()
        {
            return Protection.ToString();
        }
    }
}
