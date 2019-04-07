using _2Captcha;
using Jint;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Cloudflare
{
    public class CloudflareSolver
    {
        private struct InternalSolveResult
        {
            public readonly bool Success;
            public readonly string FailReason;

            public InternalSolveResult(bool success, string failReason)
            {
                Success = success;
                FailReason = failReason;
            }
        }

        private readonly TwoCaptcha _twoCaptcha;
        private readonly HashSet<int> _statusCodeWhitelist = new HashSet<int>
        {
            200,
            301, 307, 308,
            404, 410,
        };

        public CloudflareSolver(string _2CaptchaKey = null)
        {
            if (!string.IsNullOrEmpty(_2CaptchaKey))
                _twoCaptcha = new TwoCaptcha(_2CaptchaKey);
        }

        private bool Is2CaptchaEnabled()
        {
            return _twoCaptcha != null;
        }

        private double ExecuteJavaScript(string script)
        {
            return new Engine()
                .Execute(script)
                .GetCompletionValue()
                .AsNumber();
        }

        private void PrepareHttpHandler(HttpClientHandler httpClientHandler)
        {
            try
            {
                httpClientHandler.AllowAutoRedirect = false;
            }
            catch
            { }
        }

        private void PrepareHttpHeaders(HttpRequestHeaders headers, Uri targetUri)
        {
            if (headers.Accept.Count == 0)
                headers.Accept.ParseAdd("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8");

            if (headers.AcceptLanguage.Count == 0)
                headers.AcceptLanguage.ParseAdd("en,en-US;q=0.9");

            if (headers.Host == null)
                headers.Host = targetUri.Host;

            if (headers.Referrer == null)
                headers.Referrer = targetUri;

            if (headers.UserAgent.Count == 0)
                headers.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36");

            if (headers.Connection.Count == 0)
                headers.Connection.ParseAdd("keep-alive");

            if (!headers.Contains("DNT"))
                headers.Add("DNT", "1");

            if (!headers.Contains("Upgrade-Insecure-Requests"))
                headers.Add("Upgrade-Insecure-Requests", "1");
        }

        private string PrepareJsScript(Uri targetUri, Match defineMatch, MatchCollection calcMatches, Match htmlHiddenMatch)
        {
            var solveScriptStringBuilder = new StringBuilder(defineMatch.Value);

            foreach (Match calcMatch in calcMatches)
            {
                if (calcMatch.Value.EndsWith("}();") && calcMatch.Value.Contains("eval(eval("))
                {
                    var i = calcMatch.Value.IndexOf("function", StringComparison.Ordinal);
                    solveScriptStringBuilder.Append(calcMatch.Value.Substring(0, i) + htmlHiddenMatch.Groups["inner"].Value + ";");
                }
                else if (calcMatch.Value.EndsWith(")))));") && calcMatch.Value.Contains("return eval("))
                {
                    var match = CloudflareRegex.JsPParamRegex.Match(calcMatch.Value);
                    if (match.Success)
                    {
                        var p = match.Groups["p"].Value;
                        var i = calcMatch.Value.IndexOf("(function", StringComparison.Ordinal);
                        solveScriptStringBuilder.Append(calcMatch.Value.Substring(0, i) + $"'{targetUri.Host}'.charCodeAt({p})" + ");");
                    }
                }
                else
                {
                    solveScriptStringBuilder.Append(calcMatch.Value);
                }
            }

            solveScriptStringBuilder.Append($"+{defineMatch.Groups["className"].Value}.{defineMatch.Groups["propName"].Value}.toFixed(10)");

            return solveScriptStringBuilder.ToString();
        }

        public async Task<CloudflareSolveResult> Solve(HttpClient httpClient, HttpClientHandler httpClientHandler, Uri targetUri, int maxRetry = 3, bool validateCloudflare = true, CloudflareDetectResult detectResult = null)
        {
            var lastResult = default(CloudflareSolveResult);

            for (var i = 0; i < maxRetry; i++)
            {
                if (detectResult == null)
                    detectResult = await Detect(httpClient, httpClientHandler, targetUri, validateCloudflare);

                switch (detectResult.Protection)
                {
                    case CloudflareProtection.NoProtection:
                        lastResult = new CloudflareSolveResult
                        {
                            Success = true,
                            FailReason = "No protection detected",
                            DetectResult = detectResult,
                        };
                        break;
                    case CloudflareProtection.JavaScript:
                        {
                            var solve = await SolveJs(httpClient, targetUri, detectResult.Html);
                            lastResult = new CloudflareSolveResult
                            {
                                Success = solve.Success,
                                FailReason = solve.FailReason,
                                DetectResult = detectResult,
                            };
                        }
                        break;
                    case CloudflareProtection.Captcha:
                        {
                            if (!Is2CaptchaEnabled())
                            {
                                lastResult = new CloudflareSolveResult
                                {
                                    Success = false,
                                    FailReason = "Missing 2Captcha API key to solve the captcha",
                                    DetectResult = detectResult,
                                };
                            }

                            var solve = await SolveCaptcha(httpClient, targetUri, detectResult.Html);
                            lastResult = new CloudflareSolveResult
                            {
                                Success = solve.Success,
                                FailReason = solve.FailReason,
                                DetectResult = detectResult,
                            };
                        }
                        break;
                    case CloudflareProtection.Banned:
                        lastResult = new CloudflareSolveResult
                        {
                            Success = false,
                            FailReason = "This IP address is banned on the website",
                            DetectResult = detectResult,
                        };
                        break;
                    case CloudflareProtection.Unknown:
                        lastResult = new CloudflareSolveResult
                        {
                            Success = false,
                            FailReason = "Unknown protection detected",
                            DetectResult = detectResult,
                        };
                        break;
                    default:
                        throw new ArgumentOutOfRangeException();
                }

                if (lastResult.Success)
                    return lastResult;

                detectResult = null;
            }

            return lastResult;
        }

        public async Task<CloudflareDetectResult> Detect(HttpClient httpClient, HttpClientHandler httpClientHandler, Uri targetUri, bool validateCloudflare = true)
        {
            PrepareHttpHandler(httpClientHandler);
            PrepareHttpHeaders(httpClient.DefaultRequestHeaders, targetUri);

            await httpClient.GetAsync(targetUri);
            var response = await httpClient.GetAsync(targetUri);

            if (response.StatusCode == HttpStatusCode.ServiceUnavailable)
            {
                var html = await response.Content.ReadAsStringAsync();
                if (html.Contains("<title>Just a moment...</title>"))
                {
                    return new CloudflareDetectResult
                    {
                        Protection = CloudflareProtection.JavaScript,
                        Html = html,
                    };
                }

                return new CloudflareDetectResult
                {
                    Protection = CloudflareProtection.Unknown,
                    Html = html,
                };
            }

            if (response.StatusCode == HttpStatusCode.Forbidden)
            {
                var html = await response.Content.ReadAsStringAsync();
                if (html.Contains("<title>Attention Required! |"))
                {
                    return new CloudflareDetectResult
                    {
                        Protection = CloudflareProtection.Captcha,
                        Html = html,
                    };
                }

                if (html.Contains("<title>Access denied |"))
                {
                    return new CloudflareDetectResult
                    {
                        Protection = CloudflareProtection.Banned,
                        Html = html,
                    };
                }

                return new CloudflareDetectResult
                {
                    Protection = CloudflareProtection.Unknown,
                    Html = html,
                };
            }

            if ((!validateCloudflare || response.Headers.Contains("CF-RAY")) && (response.IsSuccessStatusCode || _statusCodeWhitelist.Contains((int)response.StatusCode)))
            {
                return new CloudflareDetectResult
                {
                    Protection = CloudflareProtection.NoProtection,
                };
            }

            return new CloudflareDetectResult
            {
                Protection = CloudflareProtection.Unknown,
            };
        }

        private async Task<InternalSolveResult> SolveJs(HttpClient httpClient, Uri targetUri, string html)
        {
            var formMatch = CloudflareRegex.JsFormRegex.Match(html);
            if (!formMatch.Success)
            {
                return new InternalSolveResult(false, "Cloudflare (JS): form tag not found");
            }

            var htmlHidden = CloudflareRegex.JsHtmlHiddenRegex.Match(html);
            if (!htmlHidden.Success)
            {
                return new InternalSolveResult(false, "Cloudflare (JS): hidden html not found");
            }

            var scriptMatch = CloudflareRegex.ScriptRegex.Match(html);
            if (!scriptMatch.Success)
            {
                return new InternalSolveResult(false, "Cloudflare (JS): script tag not found");
            }

            var script = scriptMatch.Groups["script"].Value;

            var defineMatch = CloudflareRegex.JsDefineRegex.Match(script);
            if (!defineMatch.Success)
            {
                return new InternalSolveResult(false, "Cloudflare (JS): define variable not found");
            }

            var calcMatches = CloudflareRegex.JsCalcRegex.Matches(script);
            if (calcMatches.Count == 0)
            {
                return new InternalSolveResult(false, "Cloudflare (JS): challenge not found");
            }

            var solveJsScript = PrepareJsScript(targetUri, defineMatch, calcMatches, htmlHidden);

            var action = $"{targetUri.Scheme}://{targetUri.Host}{formMatch.Groups["action"]}";
            var s = formMatch.Groups["s"].Value;
            var jschl_vc = formMatch.Groups["jschl_vc"].Value;
            var pass = formMatch.Groups["pass"].Value;
            var jschl_answer = ExecuteJavaScript(solveJsScript).ToString(CultureInfo.InvariantCulture);

            await Task.Delay(4000 + 100);

            return await SubmitJsSolution(httpClient, action, s, jschl_vc, pass, jschl_answer);
        }

        private async Task<InternalSolveResult> SubmitJsSolution(HttpClient httpClient, string action, string s, string jschl_vc, string pass, string jschl_answer)
        {
            var query = $"s={Uri.EscapeDataString(s)}&jschl_vc={Uri.EscapeDataString(jschl_vc)}&pass={Uri.EscapeDataString(pass)}&jschl_answer={Uri.EscapeDataString(jschl_answer)}";

            var response = await httpClient.GetAsync($"{action}?{query}");
            if (response.StatusCode != HttpStatusCode.Found)
            {
                return new InternalSolveResult(false, "Cloudflare (JS): invalid submit response");
            }

            var success = response.Headers.Contains("Set-Cookie");
            return new InternalSolveResult(success, success ? null : "Cloudflare (JS): response cookie not found");
        }

        private async Task<InternalSolveResult> SolveCaptcha(HttpClient httpClient, Uri targetUri, string html)
        {
            var formMatch = CloudflareRegex.CaptchaFormRegex.Match(html);
            if (!formMatch.Success)
            {
                return new InternalSolveResult(false, "Cloudflare (Captcha): form tag not found");
            }

            var action = $"{targetUri.Scheme}://{targetUri.Host}{formMatch.Groups["action"]}";
            var siteKey = formMatch.Groups["siteKey"].Value;

            var captchaResult = await _twoCaptcha.SolveReCaptchaV2(siteKey, targetUri.AbsoluteUri);
            if (!captchaResult.Success)
            {
                return new InternalSolveResult(false, $"Cloudflare (Captcha): 2Captcha error ({captchaResult.Response})");
            }

            return await SubmitCaptchaSolution(httpClient, action, captchaResult.Response);
        }

        private async Task<InternalSolveResult> SubmitCaptchaSolution(HttpClient httpClient, string action, string captchaResponse)
        {
            var query = $"g-recaptcha-response={Uri.EscapeDataString(captchaResponse)}";

            var response = await httpClient.GetAsync($"{action}?{query}");
            if (response.StatusCode != HttpStatusCode.Found)
            {
                return new InternalSolveResult(false, "Cloudflare (Captcha): invalid submit response");
            }

            var success = response.Headers.Contains("Set-Cookie");
            return new InternalSolveResult(success, success ? null : "Cloudflare (Captcha): response cookie not found");
        }

    }
}
