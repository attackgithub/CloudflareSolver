using _AntiCaptcha;
using Cloudflare.Interfaces;
using Cloudflare.Structs;
using System.Threading.Tasks;

namespace Cloudflare.CaptchaProviders
{
    public class AntiCaptchaProvider : ICaptchaProvider
    {
        public string Name { get; } = "AntiCaptcha";

        private readonly AntiCaptcha _antiCaptcha;

        public AntiCaptchaProvider(string apiKey)
        {
            _antiCaptcha = new AntiCaptcha(apiKey);
        }

        public async Task<CaptchaSolveResult> SolveCaptcha(string siteKey, string webUrl)
        {
            var result = await _antiCaptcha.SolveReCaptchaV2(siteKey, webUrl);

            return new CaptchaSolveResult
            {
                Success = result.Success,
                Response = result.Response,
            };
        }
    }
}
