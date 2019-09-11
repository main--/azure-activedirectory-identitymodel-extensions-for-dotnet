//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols.PoP
{
    /// <summary>
    /// 
    /// </summary>
    public class PopAuthenticationHandler
    {
        private readonly JsonWebTokenHandler _handler = new JsonWebTokenHandler();
        private readonly Uri _baseUriHelper = new Uri("http://localhost", UriKind.Absolute);
        private readonly HttpClient _defaultHttpClient = new HttpClient();
        private readonly string _newlineSeparator = "\n";

        #region Pop authenticator creation
        /// <summary>
        /// 
        /// </summary>
        /// <param name="tokenWithCnfClaim"></param>
        /// <param name="signingCredentials"></param>
        /// <param name="httpRequestData"></param>
        /// <param name="popAuthenticatorCreationPolicy"></param>
        /// <returns></returns>
        public virtual string CreatePopAuthenticator(string tokenWithCnfClaim, SigningCredentials signingCredentials, HttpRequestData httpRequestData, PopAuthenticatorCreationPolicy popAuthenticatorCreationPolicy)
        {
            var header = CreatePopAuthenticatorHeader(signingCredentials, popAuthenticatorCreationPolicy);
            var payload = CreatePopAuthenticatorPayload(tokenWithCnfClaim, httpRequestData, popAuthenticatorCreationPolicy);
            return SignPopAuthenticator(header, payload, signingCredentials);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="signingCredentials"></param>
        /// <param name="popAuthenticatorCreationPolicy"></param>
        /// <returns></returns>
        protected virtual string CreatePopAuthenticatorHeader(SigningCredentials signingCredentials, PopAuthenticatorCreationPolicy popAuthenticatorCreationPolicy)
        {
            if (signingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(signingCredentials));

            var header = new JObject
            {
                { JwtHeaderParameterNames.Alg, signingCredentials.Algorithm },
                { JwtHeaderParameterNames.Typ, JwtConstants.HeaderType }
            };

            if (signingCredentials.Key?.KeyId != null)
                header.Add(JwtHeaderParameterNames.Kid, signingCredentials.Key.KeyId);

            if (signingCredentials.Key is X509SecurityKey x509SecurityKey)
                header[JwtHeaderParameterNames.X5t] = x509SecurityKey.X5t;

            return header.ToString(Formatting.None);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="tokenWithCnfClaim"></param>
        /// <param name="httpRequestData"></param>
        /// <param name="popAuthenticatorCreationPolicy"></param>
        /// <returns></returns>
        protected virtual string CreatePopAuthenticatorPayload(string tokenWithCnfClaim, HttpRequestData httpRequestData, PopAuthenticatorCreationPolicy popAuthenticatorCreationPolicy)
        {
            if (popAuthenticatorCreationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popAuthenticatorCreationPolicy));

            Dictionary<string, object> payload = new Dictionary<string, object>();

            AddAtClaim(payload, tokenWithCnfClaim);

            if (popAuthenticatorCreationPolicy.CreateTs)
                AddTsClaim(payload, popAuthenticatorCreationPolicy);

            if (popAuthenticatorCreationPolicy.CreateM)
                AddMClaim(payload, httpRequestData?.HttpMethod);

            if (popAuthenticatorCreationPolicy.CreateU)
                AddUClaim(payload, httpRequestData?.HttpRequestUri);

            if (popAuthenticatorCreationPolicy.CreateP)
                AddPClaim(payload, httpRequestData?.HttpRequestUri, popAuthenticatorCreationPolicy);

            if (popAuthenticatorCreationPolicy.CreateQ)
                AddQClaim(payload, httpRequestData?.HttpRequestUri, popAuthenticatorCreationPolicy);

            if (popAuthenticatorCreationPolicy.CreateH)
                AddHClaim(payload, httpRequestData?.HttpRequestHeaders, popAuthenticatorCreationPolicy);

            if (popAuthenticatorCreationPolicy.CreateB)
                AddBClaim(payload, httpRequestData?.HttpRequestBody, popAuthenticatorCreationPolicy);

            if (popAuthenticatorCreationPolicy.CreateNonce)
                AddNonceClaim(payload);

            return JObject.FromObject(payload).ToString(Formatting.None);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="header"></param>
        /// <param name="payload"></param>
        /// <param name="signingCredentials"></param>
        /// <returns></returns>
        protected virtual string SignPopAuthenticator(string header, string payload, SigningCredentials signingCredentials)
        {
            if (string.IsNullOrEmpty(header))
                throw LogHelper.LogArgumentNullException(nameof(header));

            if (string.IsNullOrEmpty(payload))
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (signingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(signingCredentials));

            var cryptoFactory = signingCredentials.CryptoProviderFactory ?? signingCredentials.Key.CryptoProviderFactory;
            var signatureProvider = cryptoFactory.CreateForSigning(signingCredentials.Key, signingCredentials.Algorithm);
            if (signatureProvider == null)
                throw LogHelper.LogExceptionMessage(new PopProtocolCreationException(LogHelper.FormatInvariant(LogMessages.IDX23000, (signingCredentials.Key == null ? "Null" : signingCredentials.Key.ToString()), (signingCredentials.Algorithm ?? "Null"))));
            try
            {
                var message = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header)) + "." + Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload));
                var signedMessage = message + "." + Base64UrlEncoder.Encode(signatureProvider.Sign(Encoding.UTF8.GetBytes(message)));
                return signedMessage;
            }
            finally
            {
                cryptoFactory.ReleaseSignatureProvider(signatureProvider);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="tokenWithCnfClaim"></param>
        protected virtual void AddAtClaim(Dictionary<string, object> payload, string tokenWithCnfClaim)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (string.IsNullOrEmpty(tokenWithCnfClaim))
                throw LogHelper.LogArgumentNullException(nameof(tokenWithCnfClaim));

            payload.Add(PopConstants.ClaimTypes.At, tokenWithCnfClaim);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="popAuthenticatorCreationPolicy"></param>
        protected virtual void AddTsClaim(Dictionary<string, object> payload, PopAuthenticatorCreationPolicy popAuthenticatorCreationPolicy)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (popAuthenticatorCreationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popAuthenticatorCreationPolicy));

            var authenticatorCreationTime = DateTime.UtcNow.Add(popAuthenticatorCreationPolicy.ClockSkew);
            payload.Add(PopConstants.ClaimTypes.Ts, (long)(authenticatorCreationTime - EpochTime.UnixEpoch).TotalSeconds);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="httpMethod"></param>
        protected virtual void AddMClaim(Dictionary<string, object> payload, string httpMethod)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (string.IsNullOrEmpty(httpMethod))
                throw LogHelper.LogArgumentNullException(nameof(httpMethod));

            if (!httpMethod.ToUpper().Equals(httpMethod, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new PopProtocolCreationException(LogHelper.FormatInvariant(LogMessages.IDX23002, httpMethod)));

            payload.Add(PopConstants.ClaimTypes.M, httpMethod);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="httpRequestUri"></param>
        protected virtual void AddUClaim(Dictionary<string, object> payload, Uri httpRequestUri)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestUri));

            if (!httpRequestUri.IsAbsoluteUri)
                throw LogHelper.LogExceptionMessage(new PopProtocolCreationException(LogHelper.FormatInvariant(LogMessages.IDX23001, httpRequestUri.ToString())));

            // https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3
            // u claim: The HTTP URL host component as a JSON string. This MAY include the port separated from the host by a colon in host:port format.
            // Including the port if it not the default port for the httpRequestUri scheme.
            var httpUrlHostComponent = httpRequestUri.Host;
            if (!httpRequestUri.IsDefaultPort)
                httpUrlHostComponent = $"{httpUrlHostComponent}:{httpRequestUri.Port}";

            payload.Add(PopConstants.ClaimTypes.U, httpUrlHostComponent);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="httpRequestUri"></param>
        /// <param name="popAuthenticatorCreationPolicy"></param>
        protected virtual void AddPClaim(Dictionary<string, object> payload, Uri httpRequestUri, PopAuthenticatorCreationPolicy popAuthenticatorCreationPolicy)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestUri));

            if (!httpRequestUri.IsAbsoluteUri)
            {
                if (!Uri.TryCreate(_baseUriHelper, httpRequestUri, out httpRequestUri))
                    throw LogHelper.LogExceptionMessage(new PopProtocolCreationException(LogHelper.FormatInvariant(LogMessages.IDX23007, httpRequestUri.ToString())));
            }

            payload.Add(PopConstants.ClaimTypes.P, httpRequestUri.AbsolutePath.TrimEnd('/'));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="httpRequestUri"></param>
        /// <param name="popAuthenticatorCreationPolicy"></param>
        protected virtual void AddQClaim(Dictionary<string, object> payload, Uri httpRequestUri, PopAuthenticatorCreationPolicy popAuthenticatorCreationPolicy)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestUri));

            if (!httpRequestUri.IsAbsoluteUri)
            {
                 if (!Uri.TryCreate(_baseUriHelper, httpRequestUri, out httpRequestUri))
                    throw LogHelper.LogExceptionMessage(new PopProtocolCreationException(LogHelper.FormatInvariant(LogMessages.IDX23007, httpRequestUri.ToString())));
            }

            var sanitizedQueryParams = SanitizeQueryParams(httpRequestUri);

            StringBuilder stringBuffer = new StringBuilder();
            List<string> queryParamNameList = new List<string>();
            try
            {
                var lastQueryParam = sanitizedQueryParams.Last();
                foreach (var queryParam in sanitizedQueryParams)
                {
                    queryParamNameList.Add(queryParam.Key);
                    var encodedValue = $"{queryParam.Key}={queryParam.Value}";

                    if (!queryParam.Equals(lastQueryParam))
                        encodedValue += "&";

                    stringBuffer.Append(encodedValue);
                }

                var base64UrlEncodedHash = CalculateBase64UrlEncodedHash(stringBuffer.ToString());
                payload.Add(PopConstants.ClaimTypes.Q, new List<object>() { queryParamNameList, base64UrlEncodedHash });
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new PopProtocolCreationException(LogHelper.FormatInvariant(LogMessages.IDX23008, PopConstants.ClaimTypes.Q, e), e));
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="httpRequestHeaders"></param>
        /// <param name="popAuthenticatorCreationPolicy"></param>
        protected virtual void AddHClaim(Dictionary<string, object> payload, IDictionary<string, IEnumerable<string>> httpRequestHeaders, PopAuthenticatorCreationPolicy popAuthenticatorCreationPolicy)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (httpRequestHeaders == null || !httpRequestHeaders.Any())
                throw LogHelper.LogArgumentNullException(nameof(httpRequestHeaders));

            var sanitizedHeaders = SanitizeHeaders(httpRequestHeaders);

            StringBuilder stringBuffer = new StringBuilder();
            List<string> headerNameList = new List<string>();
            try
            {
                var lastHeader = sanitizedHeaders.Last();
                foreach (var header in sanitizedHeaders)
                {
                    var headerName = header.Key.ToLower();
                    headerNameList.Add(headerName);

                    var encodedValue = $"{headerName}: {header.Value}";
                    if (header.Equals(lastHeader))
                        stringBuffer.Append(encodedValue);
                    else
                        // (https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3.2)
                        // Encodes the name and value of the header as "name: value" and appends it to the string buffer separated by a newline "\n" character.
                        //
                        // GK: The spec holds a wrong example of the hash. Value "bZA981YJBrPlIzOvplbu3e7ueREXXr38vSkxIBYOaxI" is calculated using the "\r\n" separator, and not "\n".
                        // Spec authors probably used Environment.NewLine or stringBuilder.AppendLine which appends "\r\n" on non-Unix platforms.
                        // The correct hash value should be "P6z5XN4tTzHkfwe3XO1YvVUIurSuhvh_UG10N_j-aGs".
                        stringBuffer.Append(encodedValue + _newlineSeparator);
                }

                var base64UrlEncodedHash = CalculateBase64UrlEncodedHash(stringBuffer.ToString());
                payload.Add(PopConstants.ClaimTypes.H, new List<object>() { headerNameList, base64UrlEncodedHash });
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new PopProtocolCreationException(LogHelper.FormatInvariant(LogMessages.IDX23008, PopConstants.ClaimTypes.H, e), e));
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="httpRequestBody"></param>
        /// <param name="popAuthenticatorCreationPolicy"></param>
        protected virtual void AddBClaim(Dictionary<string, object> payload, byte[] httpRequestBody, PopAuthenticatorCreationPolicy popAuthenticatorCreationPolicy)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (httpRequestBody == null || httpRequestBody.Count() == 0)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestBody));

            try
            {
                var base64UrlEncodedHash = CalculateBase64UrlEncodedHash(httpRequestBody);
                payload.Add(PopConstants.ClaimTypes.B, base64UrlEncodedHash);
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new PopProtocolCreationException(LogHelper.FormatInvariant(LogMessages.IDX23008, PopConstants.ClaimTypes.B, e), e));
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        protected virtual void AddNonceClaim(Dictionary<string, object> payload)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            payload.Add(PopConstants.ClaimTypes.Nonce, Guid.NewGuid().ToString("N"));
        }
        #endregion

        #region Pop authenticator validation
        /// <summary>
        ///
        /// </summary>
        /// <param name="authenticator"></param>
        /// <param name="httpRequestData"></param>
        /// <param name="tokenValidationParameters"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual async Task<PopAuthenticatorValidationResult> ValidatePopAuthenticatorAsync(string authenticator, HttpRequestData httpRequestData, TokenValidationParameters tokenValidationParameters, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(authenticator))
                throw LogHelper.LogArgumentNullException(nameof(authenticator));

            var jwtAuthenticator = _handler.ReadJsonWebToken(authenticator);
            if (!jwtAuthenticator.TryGetPayloadValue(PopConstants.ClaimTypes.At, out string accessToken) || accessToken == null)
            {
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidAtClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, PopConstants.ClaimTypes.At)));
            }
            var validatedToken = await ValidateTokenAsync(accessToken, tokenValidationParameters, cancellationToken).ConfigureAwait(false) as JsonWebToken;
            await ValidateAuthenticatorAsync(jwtAuthenticator, validatedToken, httpRequestData, popAuthenticatorValidationPolicy, cancellationToken).ConfigureAwait(false);

            return new PopAuthenticatorValidationResult()
            {
                AccessToken = validatedToken.EncodedToken,
                Authenticator = jwtAuthenticator.EncodedToken,
                ValidatedAccessToken = validatedToken
            };
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtAuthenticator"></param>
        /// <param name="validatedToken"></param>
        /// <param name="httpRequestData"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        protected virtual async Task ValidateAuthenticatorAsync(JsonWebToken jwtAuthenticator, JsonWebToken validatedToken, HttpRequestData httpRequestData, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy, CancellationToken cancellationToken)
        {
            if (jwtAuthenticator == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtAuthenticator));

            if (popAuthenticatorValidationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popAuthenticatorValidationPolicy));

            if (popAuthenticatorValidationPolicy.AuthenticatorReplayValidatorAsync != null)
                await popAuthenticatorValidationPolicy.AuthenticatorReplayValidatorAsync(jwtAuthenticator, cancellationToken).ConfigureAwait(false);

            await ValidateAuthenticatorSignatureAsync(jwtAuthenticator, validatedToken, popAuthenticatorValidationPolicy, cancellationToken).ConfigureAwait(false);

            if (popAuthenticatorValidationPolicy.ValidateTs)
                ValidateTsClaim(jwtAuthenticator, popAuthenticatorValidationPolicy);

            if (popAuthenticatorValidationPolicy.ValidateM)
                ValidateMClaim(jwtAuthenticator, httpRequestData?.HttpMethod);

            if (popAuthenticatorValidationPolicy.ValidateU)
                ValidateUClaim(jwtAuthenticator, httpRequestData?.HttpRequestUri);

            if (popAuthenticatorValidationPolicy.ValidateP)
                ValidatePClaim(jwtAuthenticator, httpRequestData?.HttpRequestUri);

            if (popAuthenticatorValidationPolicy.ValidateQ)
                ValidateQClaim(jwtAuthenticator, httpRequestData?.HttpRequestUri, popAuthenticatorValidationPolicy);

            if (popAuthenticatorValidationPolicy.ValidateH)
                ValidateHClaim(jwtAuthenticator, httpRequestData?.HttpRequestHeaders, popAuthenticatorValidationPolicy);

            if (popAuthenticatorValidationPolicy.ValidateB)
                ValidateBClaim(jwtAuthenticator, httpRequestData?.HttpRequestBody);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtAuthenticator"></param>
        /// <param name="validatedToken"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        /// <param name="cancellationToken"></param>
        protected virtual async Task ValidateAuthenticatorSignatureAsync(JsonWebToken jwtAuthenticator, JsonWebToken validatedToken, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy, CancellationToken cancellationToken)
        {
            if (jwtAuthenticator == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtAuthenticator));

            var popKey = await ResolvePopKeyAsync(validatedToken, popAuthenticatorValidationPolicy, cancellationToken).ConfigureAwait(false);
            if (popKey == null)
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidSignatureException(LogHelper.FormatInvariant(LogMessages.IDX23030)));

            var signatureProvider = popKey.CryptoProviderFactory.CreateForVerifying(popKey, jwtAuthenticator.Alg);
            if (signatureProvider == null)
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidSignatureException(LogHelper.FormatInvariant(LogMessages.IDX23000, popKey?.ToString() ?? "Null", jwtAuthenticator.Alg ?? "Null")));

            try
            {
                var encodedBytes = Encoding.UTF8.GetBytes(jwtAuthenticator.EncodedHeader + "." + jwtAuthenticator.EncodedPayload);
                var signature = Base64UrlEncoder.DecodeBytes(jwtAuthenticator.EncodedSignature);

                if (!signatureProvider.Verify(encodedBytes, signature))
                    throw LogHelper.LogExceptionMessage(new PopProtocolInvalidSignatureException(LogHelper.FormatInvariant(LogMessages.IDX23009)));
            }
            finally
            {
                popKey.CryptoProviderFactory.ReleaseSignatureProvider(signatureProvider);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtAuthenticator"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        protected virtual void ValidateTsClaim(JsonWebToken jwtAuthenticator, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy)
        {
            if (jwtAuthenticator == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtAuthenticator));

            if (popAuthenticatorValidationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popAuthenticatorValidationPolicy));

            if (!jwtAuthenticator.TryGetPayloadValue(PopConstants.ClaimTypes.Ts, out long tsClaimValue))
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidTsClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, PopConstants.ClaimTypes.Ts)));

            DateTime utcNow = DateTime.UtcNow;
            DateTime authenticatorCreationTime = EpochTime.DateTime(tsClaimValue);
            DateTime authenticatorExpirationTime = authenticatorCreationTime.Add(popAuthenticatorValidationPolicy.AuthenticatorLifetime);

            if (utcNow > authenticatorExpirationTime)
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidTsClaimException(LogHelper.FormatInvariant(LogMessages.IDX23010, utcNow, authenticatorExpirationTime)));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtAuthenticator"></param>
        /// <param name="expectedHttpMethod"></param>
        protected virtual void ValidateMClaim(JsonWebToken jwtAuthenticator, string expectedHttpMethod)
        {
            if (jwtAuthenticator == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtAuthenticator));

            if (string.IsNullOrEmpty(expectedHttpMethod))
                throw LogHelper.LogArgumentNullException(nameof(expectedHttpMethod));

            if (!jwtAuthenticator.TryGetPayloadValue(PopConstants.ClaimTypes.M, out string httpMethod) || httpMethod == null)
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidMClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, PopConstants.ClaimTypes.M)));

            // "get " is functionally the same as "GET".
            // different implementations might use differently formatted http verbs and we shouldn't fault.
            httpMethod = httpMethod.Trim();
            expectedHttpMethod = expectedHttpMethod.Trim();
            if (!string.Equals(expectedHttpMethod, httpMethod, StringComparison.OrdinalIgnoreCase))
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidMClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, PopConstants.ClaimTypes.M, expectedHttpMethod, httpMethod)));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtAuthenticator"></param>
        /// <param name="httpRequestUri"></param>
        protected virtual void ValidateUClaim(JsonWebToken jwtAuthenticator, Uri httpRequestUri)
        {
            if (jwtAuthenticator == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtAuthenticator));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestUri));

            if (!httpRequestUri.IsAbsoluteUri)
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidUClaimException(LogHelper.FormatInvariant(LogMessages.IDX23001, httpRequestUri.ToString())));

            if (!jwtAuthenticator.TryGetPayloadValue(PopConstants.ClaimTypes.U, out string uClaimValue) || uClaimValue == null)
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidUClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, PopConstants.ClaimTypes.U)));

            // https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3.2
            // u: The HTTP URL host component as a JSON string.
            // This MAY include the port separated from the host by a colon in host:port format.
            var expectedUClaimValue = httpRequestUri.Host;
            var expectedUClaimValueIncludingPort = $"{expectedUClaimValue}:{httpRequestUri.Port}";

            if (!string.Equals(expectedUClaimValue, uClaimValue, StringComparison.Ordinal) &&
                !string.Equals(expectedUClaimValueIncludingPort, uClaimValue, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidUClaimException(LogHelper.FormatInvariant(LogMessages.IDX23012, expectedUClaimValue, expectedUClaimValueIncludingPort, uClaimValue)));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtAuthenticator"></param>
        /// <param name="httpRequestUri"></param>
        protected virtual void ValidatePClaim(JsonWebToken jwtAuthenticator, Uri httpRequestUri)
        {
            if (jwtAuthenticator == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtAuthenticator));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestUri));

            if (!httpRequestUri.IsAbsoluteUri)
            {
                if (!Uri.TryCreate(_baseUriHelper, httpRequestUri, out httpRequestUri))
                    throw LogHelper.LogExceptionMessage(new PopProtocolInvalidPClaimException(LogHelper.FormatInvariant(LogMessages.IDX23007, httpRequestUri.ToString())));
            }

            if (!jwtAuthenticator.TryGetPayloadValue(PopConstants.ClaimTypes.P, out string pClaimValue) || pClaimValue == null)
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidPClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, PopConstants.ClaimTypes.P)));

            var expectedPClaimValue = httpRequestUri.AbsolutePath.TrimEnd('/');

            if (!string.Equals(expectedPClaimValue, pClaimValue, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidPClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, PopConstants.ClaimTypes.P, expectedPClaimValue, pClaimValue)));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtAuthenticator"></param>
        /// <param name="httpRequestUri"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        protected virtual void ValidateQClaim(JsonWebToken jwtAuthenticator, Uri httpRequestUri, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy)
        {
            if (jwtAuthenticator == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtAuthenticator));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestUri));

            if (popAuthenticatorValidationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popAuthenticatorValidationPolicy));

            if (!jwtAuthenticator.TryGetPayloadValue(PopConstants.ClaimTypes.Q, out JArray qClaim) || qClaim == null)
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, PopConstants.ClaimTypes.Q)));

            if (!httpRequestUri.IsAbsoluteUri)
            {
                if (!Uri.TryCreate(_baseUriHelper, httpRequestUri, out httpRequestUri))
                    throw LogHelper.LogExceptionMessage(new PopProtocolInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23007, httpRequestUri.ToString())));
            }

            var sanitizedQueryParams = SanitizeQueryParams(httpRequestUri);

            string qClaimBase64UrlEncodedHash = string.Empty;
            string expectedBase64UrlEncodedHash = string.Empty;
            List<string> qClaimQueryParamNames;
            try
            {
                // "q": [["queryParamName1", "queryParamName2",... "queryParamNameN"], "base64UrlEncodedHashValue"]]
                qClaimQueryParamNames = qClaim[0].ToObject<List<string>>();
                qClaimBase64UrlEncodedHash = qClaim[1].ToString();
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23024, PopConstants.ClaimTypes.Q, qClaim.ToString(), e), e));
            }

            try
            {
                StringBuilder stringBuffer = new StringBuilder();
                var lastQueryParam = qClaimQueryParamNames.LastOrDefault();
                foreach (var queryParamName in qClaimQueryParamNames)
                {
                    if (!sanitizedQueryParams.TryGetValue(queryParamName, out var queryParamsValue))
                    {
                        throw LogHelper.LogExceptionMessage(new PopProtocolInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23028, queryParamName, string.Join(", ", sanitizedQueryParams.Select(x => x.Key)))));
                    }
                    else
                    {
                        var encodedValue = $"{queryParamName}={queryParamsValue}";

                        if (!queryParamName.Equals(lastQueryParam))
                            encodedValue += "&";

                        stringBuffer.Append(encodedValue);

                        // remove the query param from the dictionary to mark it as covered.
                        sanitizedQueryParams.Remove(queryParamName);
                    }
                }

                expectedBase64UrlEncodedHash = CalculateBase64UrlEncodedHash(stringBuffer.ToString());
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23025, PopConstants.ClaimTypes.Q, e), e));
            }

            if (!popAuthenticatorValidationPolicy.AcceptUncoveredQueryParameters && sanitizedQueryParams.Any())
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23029, string.Join(", ", sanitizedQueryParams.Select(x => x.Key)))));

            if (!string.Equals(expectedBase64UrlEncodedHash, qClaimBase64UrlEncodedHash, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, PopConstants.ClaimTypes.Q, expectedBase64UrlEncodedHash, qClaimBase64UrlEncodedHash)));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtAuthenticator"></param>
        /// <param name="httpRequestHeaders"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        protected virtual void ValidateHClaim(JsonWebToken jwtAuthenticator, IDictionary<string, IEnumerable<string>> httpRequestHeaders, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy)
        {
            if (jwtAuthenticator == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtAuthenticator));

            if (httpRequestHeaders == null || !httpRequestHeaders.Any())
                throw LogHelper.LogArgumentNullException(nameof(httpRequestHeaders));

            if (popAuthenticatorValidationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popAuthenticatorValidationPolicy));

            if (!jwtAuthenticator.TryGetPayloadValue(PopConstants.ClaimTypes.H, out JArray hClaim) || hClaim == null)
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, PopConstants.ClaimTypes.H)));

            var sanitizedHeaders = SanitizeHeaders(httpRequestHeaders);

            string hClaimBase64UrlEncodedHash = string.Empty;
            string expectedBase64UrlEncodedHash = string.Empty;
            List<string> hClaimHeaderNames;
            try
            {
                // "h": [["headerName1", "headerName2",... "headerNameN"], "base64UrlEncodedHashValue"]]
                hClaimHeaderNames = hClaim[0].ToObject<List<string>>();
                hClaimBase64UrlEncodedHash = hClaim[1].ToString();
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23024, PopConstants.ClaimTypes.H, hClaim.ToString(), e), e));
            }

            try
            {
                StringBuilder stringBuffer = new StringBuilder();
                var lastHeader = hClaimHeaderNames.Last();
                foreach (var headerName in hClaimHeaderNames)
                {
                    if (!sanitizedHeaders.TryGetValue(headerName, out var headerValue))
                    {
                        throw LogHelper.LogExceptionMessage(new PopProtocolInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23027, headerName, string.Join(", ", sanitizedHeaders.Select(x => x.Key)))));
                    }
                    else
                    {
                        var encodedValue = $"{headerName}: {headerValue}";
                        if (headerName.Equals(lastHeader))
                            stringBuffer.Append(encodedValue);
                        else
                            stringBuffer.Append(encodedValue + _newlineSeparator);

                        // remove the header from the dictionary to mark it as covered.
                        sanitizedHeaders.Remove(headerName);
                    }
                }

                expectedBase64UrlEncodedHash = CalculateBase64UrlEncodedHash(stringBuffer.ToString());
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23025, PopConstants.ClaimTypes.H, e), e));
            }

            if (!popAuthenticatorValidationPolicy.AcceptUncoveredHeaders && sanitizedHeaders.Any())
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23026, string.Join(", ", sanitizedHeaders.Select(x => x.Key)))));

            if (!string.Equals(expectedBase64UrlEncodedHash, hClaimBase64UrlEncodedHash, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, PopConstants.ClaimTypes.H, expectedBase64UrlEncodedHash, hClaimBase64UrlEncodedHash)));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtAuthenticator"></param>
        /// <param name="httpRequestBody"></param>
        protected virtual void ValidateBClaim(JsonWebToken jwtAuthenticator, byte[] httpRequestBody)
        {
            if (jwtAuthenticator == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtAuthenticator));

            if (httpRequestBody == null || httpRequestBody.Count() == 0)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestBody));

            if (!jwtAuthenticator.TryGetPayloadValue(PopConstants.ClaimTypes.B, out string bClaim) || bClaim == null)
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidBClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, PopConstants.ClaimTypes.B)));

            string expectedBase64UrlEncodedHash;
            try
            {
                expectedBase64UrlEncodedHash = CalculateBase64UrlEncodedHash(httpRequestBody);
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new PopProtocolCreationException(LogHelper.FormatInvariant(LogMessages.IDX23008, PopConstants.ClaimTypes.B, e), e));
            }

            if (!string.Equals(expectedBase64UrlEncodedHash, bClaim, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidBClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, PopConstants.ClaimTypes.B, expectedBase64UrlEncodedHash, bClaim)));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="accessToken"></param>
        /// <param name="tokenValidationParameters"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        protected virtual Task<SecurityToken> ValidateTokenAsync(string accessToken, TokenValidationParameters tokenValidationParameters, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(accessToken))
                throw LogHelper.LogArgumentNullException(nameof(accessToken));

            if (tokenValidationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(tokenValidationParameters));

            var tokenValidationResult = _handler.ValidateToken(accessToken, tokenValidationParameters);

            if (!tokenValidationResult.IsValid)
            {
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidAtClaimException(LogHelper.FormatInvariant(LogMessages.IDX23013, tokenValidationResult.Exception), tokenValidationResult.Exception));
            }

            return Task.FromResult(tokenValidationResult.SecurityToken);
        }
        #endregion

        #region Resolving PoP key
        /// <summary>
        /// 
        /// </summary>
        /// <param name="validatedToken"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        protected virtual async Task<SecurityKey> ResolvePopKeyAsync(JsonWebToken validatedToken, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy, CancellationToken cancellationToken)
        {
            if (validatedToken == null)
                throw LogHelper.LogArgumentNullException(nameof(validatedToken));

            var cnf = JObject.Parse(GetCnfClaimValue(validatedToken));
            if (cnf.TryGetValue(JwtHeaderParameterNames.Jwk, StringComparison.Ordinal, out var jwk))
            {
                return ResolvePopKeyFromJwk(jwk.ToString());
            }
            else if (cnf.TryGetValue(PopConstants.ClaimTypes.Jwe, StringComparison.Ordinal, out var jwe))
            {
                return await ResolvePopKeyFromJweAsync(jwe.ToString(), popAuthenticatorValidationPolicy, cancellationToken).ConfigureAwait(false);
            }
            else if (cnf.TryGetValue(JwtHeaderParameterNames.Jku, StringComparison.Ordinal, out var jku))
            {
                if (cnf.TryGetValue(JwtHeaderParameterNames.Kid, StringComparison.Ordinal, out var kid))
                    return await ResolvePopKeyFromJkuAsync(jku.ToString(), kid.ToString(), popAuthenticatorValidationPolicy, cancellationToken).ConfigureAwait(false);
                else
                    return await ResolvePopKeyFromJkuAsync(jku.ToString(), popAuthenticatorValidationPolicy, cancellationToken).ConfigureAwait(false);
            }
            else if (cnf.TryGetValue(JwtHeaderParameterNames.Kid, StringComparison.Ordinal, out var kid))
            {
                return await ResolvePopKeyFromKidAsync(kid.ToString(), popAuthenticatorValidationPolicy, cancellationToken).ConfigureAwait(false);
            }
            else
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidCnfClaimException(LogHelper.FormatInvariant(LogMessages.IDX23014)));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="validatedToken"></param>
        /// <returns></returns>
        protected virtual string GetCnfClaimValue(JsonWebToken validatedToken)
        {
            if (validatedToken == null)
                throw LogHelper.LogArgumentNullException(nameof(validatedToken));

            if (validatedToken.TryGetPayloadValue(PopConstants.ClaimTypes.Cnf, out JObject cnf) || cnf == null)
                return cnf.ToString();
            else
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidCnfClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, PopConstants.ClaimTypes.Cnf)));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwk"></param>
        /// <returns></returns>
        protected virtual SecurityKey ResolvePopKeyFromJwk(string jwk)
        {
            if (string.IsNullOrEmpty(jwk))
                throw LogHelper.LogArgumentNullException(nameof(jwk));

            var jsonWebKey = new JsonWebKey(jwk);

            if (JsonWebKeyConverter.TryConvertToSecurityKey(jsonWebKey, out var key))
            {
                if (key is AsymmetricSecurityKey)
                    return key;
                else
                    throw LogHelper.LogExceptionMessage(new PopProtocolInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23015, key.GetType().ToString())));
            }
            else
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23016, jsonWebKey.Kid ?? "Null")));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwe"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        protected virtual async Task<SecurityKey> ResolvePopKeyFromJweAsync(string jwe, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(jwe))
                throw LogHelper.LogArgumentNullException(nameof(jwe));

            if (popAuthenticatorValidationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popAuthenticatorValidationPolicy));

            var jsonWebToken = _handler.ReadJsonWebToken(jwe);

            IEnumerable<SecurityKey> decryptionKeys;
            if (popAuthenticatorValidationPolicy.CnfDecryptionKeysResolverAsync != null)
                decryptionKeys = await popAuthenticatorValidationPolicy.CnfDecryptionKeysResolverAsync(jsonWebToken, cancellationToken).ConfigureAwait(false);
            else
                decryptionKeys = popAuthenticatorValidationPolicy.CnfDecryptionKeys;

            if (decryptionKeys == null || !decryptionKeys.Any())
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23017)));

            var tokenDecryptionParameters = new TokenValidationParameters()
            {
                TokenDecryptionKeys = decryptionKeys,
                RequireSignedTokens = false,
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = false,
            };

            JsonWebKey jsonWebKey;
            try
            {
                var decryptedJson = _handler.DecryptToken(jsonWebToken, tokenDecryptionParameters);
                jsonWebKey = new JsonWebKey(decryptedJson);
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23018, string.Join(", ", decryptionKeys.Select(x => x?.KeyId ?? "Null")), e), e));
            }

            if (JsonWebKeyConverter.TryConvertToSymmetricSecurityKey(jsonWebKey, out var symmetricKey))
                return symmetricKey;
            else
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23019, jsonWebKey.GetType().ToString())));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jku"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        protected virtual async Task<SecurityKey> ResolvePopKeyFromJkuAsync(string jku, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy, CancellationToken cancellationToken)
        {
            var popKeys = await GetPopKeysFromJkuAsync(jku, popAuthenticatorValidationPolicy, cancellationToken).ConfigureAwait(false);
            var popKeyCount = popKeys.Count;

            if (popKeyCount == 0)
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23020, popKeyCount.ToString())));
            else if (popKeyCount > 1)
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23020, popKeyCount.ToString())));
            else
                return popKeys[0];
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jku"></param>
        /// <param name="kid"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        protected virtual async Task<SecurityKey> ResolvePopKeyFromJkuAsync(string jku, string kid, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(kid))
                throw LogHelper.LogArgumentNullException(nameof(kid));

            var popKeys = await GetPopKeysFromJkuAsync(jku, popAuthenticatorValidationPolicy, cancellationToken).ConfigureAwait(false);

            foreach (var key in popKeys)
            {
                if (string.Equals(key.KeyId, kid.ToString(), StringComparison.Ordinal))
                    return key;
            }

            throw LogHelper.LogExceptionMessage(new PopProtocolInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23021, kid, string.Join(", ", popKeys.Select(x => x.KeyId ?? "Null")))));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jkuSetUrl"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        protected virtual async Task<IList<SecurityKey>> GetPopKeysFromJkuAsync(string jkuSetUrl, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(jkuSetUrl))
                throw LogHelper.LogArgumentNullException(nameof(jkuSetUrl));

            if (popAuthenticatorValidationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popAuthenticatorValidationPolicy));

            if (!Utility.IsHttps(jkuSetUrl) && popAuthenticatorValidationPolicy.RequireHttpsForJkuResourceRetrieval)
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23006, jkuSetUrl)));

            try
            {
                var httpClient = popAuthenticatorValidationPolicy.HttpClientForJkuResourceRetrieval ?? _defaultHttpClient;
                var response = await httpClient.GetAsync(jkuSetUrl, cancellationToken).ConfigureAwait(false);
                var jsonWebKey = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                var jsonWebKeySet = new JsonWebKeySet(jsonWebKey);
                return jsonWebKeySet.GetSigningKeys();
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23022, jkuSetUrl, e), e));
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="kid"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        protected virtual async Task<SecurityKey> ResolvePopKeyFromKidAsync(string kid, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(kid))
                throw LogHelper.LogArgumentNullException(nameof(kid));

            if (popAuthenticatorValidationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popAuthenticatorValidationPolicy));

            if (popAuthenticatorValidationPolicy.PopKeyIdentifierAsync != null)
                return await popAuthenticatorValidationPolicy.PopKeyIdentifierAsync(kid, cancellationToken).ConfigureAwait(false);
            else
            {
                throw LogHelper.LogExceptionMessage(new PopProtocolInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23023)));
            }
        }
        #endregion

        #region Private utility methods
        private string CalculateBase64UrlEncodedHash(string data)
        {
            return CalculateBase64UrlEncodedHash(Encoding.UTF8.GetBytes(data));
        }

        private string CalculateBase64UrlEncodedHash(byte[] bytes)
        {
            using (var hash = SHA256.Create())
            {
                var hashedBytes = hash.ComputeHash(bytes);
                return Base64UrlEncoder.Encode(hashedBytes);
            }
        }

        private Dictionary<string, string> SanitizeQueryParams(Uri httpRequestUri)
        {
            // Remove repeated query params. https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-7.5.
            // "If a header or query parameter is repeated on either the outgoing request from the client or the
            // incoming request to the protected resource, that query parameter or header name MUST NOT be covered by the hash and signature."
            var queryString = httpRequestUri.Query.TrimStart('?');
            var queryParams = queryString.Split('&').Select(x => x.Split('=')).Select(x => new KeyValuePair<string, string>(x[0], x[1])).ToList();
            var sanitizedQueryParams = new Dictionary<string, string>(StringComparer.Ordinal);
            var repeatedQueryParams = new List<string>();
            foreach (var queryParam in queryParams)
            {
                var queryParamName = queryParam.Key;

                // if sanitizedQueryParams already contain the query parameter name it means that the query parameter name is repeated.
                // in that case query parameter name should not be added, and the existing entry in sanitizedQueryParams should be removed.
                if (sanitizedQueryParams.ContainsKey(queryParamName))
                {
                    sanitizedQueryParams.Remove(queryParamName);
                    repeatedQueryParams.Add(queryParamName);
                }
                else
                {
                    sanitizedQueryParams.Add(queryParamName, queryParam.Value);
                }
            }
            if (repeatedQueryParams.Any())
            {
                LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX23004, string.Join(", ", repeatedQueryParams)));
            }

            return sanitizedQueryParams;
        }

        private IDictionary<string, IEnumerable<string>> SanitizeHeaders(IDictionary<string, IEnumerable<string>> headers)
        {
            // Remove repeated headers. https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-7.5.
            // "If a header or query parameter is repeated on either the outgoing request from the client or the
            // incoming request to the protected resource, that query parameter or header name MUST NOT be covered by the hash and signature."
            // Remove the authorization header (https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-4.1).
            var sanitizedHeaders = new Dictionary<string, IEnumerable<string>>(StringComparer.OrdinalIgnoreCase);
            var repeatedHeaders = new List<string>();
            foreach (var header in headers)
            {
                var headerName = header.Key;

                if (string.Equals(headerName, "Authorization", StringComparison.OrdinalIgnoreCase))
                    continue;

                // if sanitizedHeaders already contain the header name it means that the headerName is repeated.
                // in that case headerName should not be added, and the existing entry in sanitizedHeaders should be removed.
                if (sanitizedHeaders.ContainsKey(headerName))
                {
                    sanitizedHeaders.Remove(headerName);
                    repeatedHeaders.Add(headerName.ToLowerInvariant());
                }
                // if header has more than one value don't add it to the sanitizedHeaders as it's repeated.
                else if (header.Value.Count() > 1)
                {
                    repeatedHeaders.Add(headerName.ToLowerInvariant());
                }
                else
                    sanitizedHeaders.Add(headerName, header.Value);
            }

            if (repeatedHeaders.Any())
                LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX23005, string.Join(", ", repeatedHeaders)));

            return sanitizedHeaders;
        }
        #endregion
    }
}
