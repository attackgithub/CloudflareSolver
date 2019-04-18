﻿using _2Captcha;
using Cloudflare.Interfaces;
using Cloudflare.Structs;
using System.Threading.Tasks;

namespace Cloudflare.CaptchaProviders
{
    public class TwoCaptchaProvider : ICaptchaProvider
    {
        public string Name { get; } = "2Captcha";

        private readonly TwoCaptcha _twoCaptcha;

        public TwoCaptchaProvider(string apiKey)
        {
            _twoCaptcha = new TwoCaptcha(apiKey);
        }

        public async Task<CaptchaSolveResult> SolveCaptcha(string siteKey, string webUrl)
        {
            var result = await _twoCaptcha.SolveReCaptchaV2(siteKey, webUrl);

            return new CaptchaSolveResult
            {
                Success = result.Success,
                Response = result.Response,
            };
        }
    }
}
