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

namespace Microsoft.IdentityModel.Protocols.PoP
{
    /// <summary>
    /// 
    /// </summary>
    public class PopAuthenticationHandler : IPopAuthenticatorCreator, IPopAuthenticatorValidator
    {
        private readonly JsonWebTokenHandler _handler = new JsonWebTokenHandler();
        private readonly Uri _baseUriHelper = new Uri("http://localhost", UriKind.Absolute);
        private readonly HttpClient _defaultHttpClient = new HttpClient();


        // All hashes SHALL be calculated using the SHA256 algorithm.
        // https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3
        private readonly HashAlgorithm _hash = SHA256.Create();

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
            var header = CreatePopAuthenticatorHeader(signingCredentials);
            var payload = CreatePopAuthenticatorPayload(tokenWithCnfClaim, httpRequestData, popAuthenticatorCreationPolicy);
            return SignPopAuthenticator(header, payload, signingCredentials);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        protected virtual string CreatePopAuthenticatorHeader(SigningCredentials signingCredentials)
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
                AddTsClaim(payload);

            if (popAuthenticatorCreationPolicy.CreateM)
                AddMClaim(payload, httpRequestData?.HttpMethod);

            if (popAuthenticatorCreationPolicy.CreateU)
                AddUClaim(payload, httpRequestData?.HttpRequestUri);

            if (popAuthenticatorCreationPolicy.CreateP)
                AddPClaim(payload, httpRequestData?.HttpRequestUri);

            if (popAuthenticatorCreationPolicy.CreateQ)
                AddQClaim(payload, httpRequestData?.HttpRequestUri);

            if (popAuthenticatorCreationPolicy.CreateH)
                AddHClaim(payload, httpRequestData?.HttpRequestHeaders);

            if (popAuthenticatorCreationPolicy.CreateB)
                AddBClaim(payload, httpRequestData?.HttpRequestBody);

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
                throw LogHelper.LogExceptionMessage(new PopProtocolException(LogHelper.FormatInvariant(LogMessages.IDX23000, (signingCredentials.Key == null ? "Null" : signingCredentials.Key.ToString()), (signingCredentials.Algorithm ?? "Null"))));
            try
            {
                var message = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header)) + "." + Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload));
                return message + "." + Base64UrlEncoder.Encode(signatureProvider.Sign(Encoding.UTF8.GetBytes(message)));
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
        protected virtual void AddTsClaim(Dictionary<string, object> payload)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            payload.Add(PopConstants.ClaimTypes.Ts, (long)(DateTime.UtcNow - EpochTime.UnixEpoch).TotalSeconds);
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
                throw LogHelper.LogExceptionMessage(new PopProtocolException(LogHelper.FormatInvariant(LogMessages.IDX23002, httpMethod)));

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
                throw LogHelper.LogExceptionMessage(new PopProtocolException(LogHelper.FormatInvariant(LogMessages.IDX23001, httpRequestUri.OriginalString)));

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
        protected virtual void AddPClaim(Dictionary<string, object> payload, Uri httpRequestUri)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestUri));

            if (!httpRequestUri.IsAbsoluteUri)
            {
                if (!Uri.TryCreate(_baseUriHelper, httpRequestUri, out httpRequestUri))
                    throw new PopProtocolException("TODO");
            }

            payload.Add(PopConstants.ClaimTypes.P, httpRequestUri.AbsolutePath.TrimEnd('/'));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="httpRequestUri"></param>
        protected virtual void AddQClaim(Dictionary<string, object> payload, Uri httpRequestUri)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestUri));

            if (!httpRequestUri.IsAbsoluteUri)
            {
                 if (!Uri.TryCreate(_baseUriHelper, httpRequestUri, out httpRequestUri))
                    throw new PopProtocolException("TODO");
            }

            StringBuilder stringBuffer = new StringBuilder();
            List<string> queryParamNameList = new List<string>();
            try
            {
                var queryString = httpRequestUri.Query.TrimStart('?');
                var queryParams = queryString.Split('&').Select(x => x.Split('=')).Select(x => new KeyValuePair<string, string>(x[0], x[1])).ToList();

                // eliminate duplicate query params.
                // https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-7.5
                // If a header or query parameter is repeated on either the outgoing request from the client or the
                // incoming request to the protected resource, that query parameter or header name MUST NOT be covered by the hash and signature.
                var repeatedQueryParams = queryParams.GroupBy(x => x.Key, StringComparer.Ordinal).Where(x => x.Count() > 1).Select(x => x.Key).ToList();

                if (repeatedQueryParams.Any())
                {
                    LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX23004, string.Join(", ", repeatedQueryParams)));
                    queryParams.RemoveAll(x => repeatedQueryParams.Contains(x.Key, StringComparer.Ordinal));
                }

                var lastQueryParam = queryParams.Last();
                foreach (var queryParam in queryParams)
                {
                    queryParamNameList.Add(queryParam.Key);
                    var encodedValue = $"{queryParam.Key}={queryParam.Value}";

                    if (!queryParam.Equals(lastQueryParam))
                        encodedValue += "&";

                    stringBuffer.Append(encodedValue);
                }

                var stringBufferBytes = Encoding.UTF8.GetBytes(stringBuffer.ToString());
                var hashedStringBufferBytes = _hash.ComputeHash(stringBufferBytes);
                var base64EncodedHash = Base64UrlEncoder.Encode(hashedStringBufferBytes);

                payload.Add(PopConstants.ClaimTypes.Q, new List<object>() { queryParamNameList, base64EncodedHash });
            }
            catch (Exception e)
            {
                throw new PopProtocolException("TODO", e);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="httpRequestHeaders"></param>
        protected virtual void AddHClaim(Dictionary<string, object> payload, IEnumerable<KeyValuePair<string, IEnumerable<string>>> httpRequestHeaders)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (httpRequestHeaders == null || !httpRequestHeaders.Any())
                throw LogHelper.LogArgumentNullException(nameof(httpRequestHeaders));

            StringBuilder stringBuffer = new StringBuilder();
            List<string> headerNameList = new List<string>();
            try
            {
                // eliminate duplicate headers.
                // todo: create util
                // https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-7.5
                // If a header or query parameter is repeated on either the outgoing request from the client or the
                // incoming request to the protected resource, that query parameter or header name MUST NOT be covered by the hash and signature.
                var repeatedHeaders = httpRequestHeaders.GroupBy(x => x.Key, StringComparer.OrdinalIgnoreCase).Where(x => x.Count() > 1).Select(x => x.Key).ToList();
                if (repeatedHeaders.Any())
                {
                    LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX23005, string.Join(", ", repeatedHeaders)));
                    httpRequestHeaders = httpRequestHeaders.Where(x => !repeatedHeaders.Contains(x.Key, StringComparer.OrdinalIgnoreCase));
                }

                var lastHeader = httpRequestHeaders.Last();
                foreach (var header in httpRequestHeaders)
                {
                    var headerName = header.Key.ToLower();
                    headerNameList.Add(headerName);

                    var encodedValue = $"{headerName}: {string.Join(", ", header.Value)}";
                    if (header.Equals(lastHeader))
                        stringBuffer.Append(encodedValue);
                    else
                        // (https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3.2)
                        // Encodes the name and value of the header as "name: value" and appends it to the string buffer separated by a newline "\n" character.
                        //
                        // GK: The spec holds a wrong example of the hash. Value "bZA981YJBrPlIzOvplbu3e7ueREXXr38vSkxIBYOaxI" is calculated using the "\r\n" separator, and not "\n".
                        // Spec authors probably used Environment.NewLine or stringBuilder.AppendLine which appends "\r\n" on non-Unix platforms.
                        // The correct hash value should be "P6z5XN4tTzHkfwe3XO1YvVUIurSuhvh_UG10N_j-aGs".
                        stringBuffer.Append(encodedValue + "\n");
                }

                var stringBufferBytes = Encoding.UTF8.GetBytes(stringBuffer.ToString());
                var hashedStringBufferBytes = _hash.ComputeHash(stringBufferBytes);
                var base64EncodedHash = Base64UrlEncoder.Encode(hashedStringBufferBytes);

                payload.Add(PopConstants.ClaimTypes.H, new List<object>() { headerNameList, base64EncodedHash });
            }
            catch (Exception e)
            {
                throw new PopProtocolException("TODO", e);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="httpRequestBody"></param>
        protected virtual void AddBClaim(Dictionary<string, object> payload, byte[] httpRequestBody)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (httpRequestBody == null || httpRequestBody.Count() == 0)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestBody));

            try
            {
                var hashedRequestBody = _hash.ComputeHash(httpRequestBody);
                var base64UrlEncodedHash = Base64UrlEncoder.Encode(hashedRequestBody);
                payload.Add(PopConstants.ClaimTypes.B, base64UrlEncodedHash);
            }
            catch (Exception e)
            {
                throw new PopProtocolException("TODO", e);
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

        /// <summary>
        ///
        /// </summary>
        /// <param name="authenticator"></param>
        /// <param name="httpRequestData"></param>
        /// <param name="tokenValidationParameters"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        /// <returns></returns>
        public PopAuthenticatorValidationResult ValidatePopAuthenticator(string authenticator, HttpRequestData httpRequestData, TokenValidationParameters tokenValidationParameters, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy)
        {
            if (string.IsNullOrEmpty(authenticator))
                throw LogHelper.LogArgumentNullException(nameof(authenticator));

            var jwtAuthenticator = _handler.ReadJsonWebToken(authenticator);
            if (!jwtAuthenticator.TryGetPayloadValue(PopConstants.ClaimTypes.At, out string accessToken))
            {
                throw LogHelper.LogExceptionMessage(new PopProtocolException(LogHelper.FormatInvariant(LogMessages.IDX23003)));
            }
            var validatedToken = ValidateToken(accessToken, tokenValidationParameters) as JsonWebToken;
            ValidateAuthenticator(jwtAuthenticator, validatedToken, httpRequestData, popAuthenticatorValidationPolicy);

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
        /// <returns></returns>
        protected virtual void ValidateAuthenticator(JsonWebToken jwtAuthenticator, JsonWebToken validatedToken, HttpRequestData httpRequestData, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy)
        {
            if (jwtAuthenticator == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtAuthenticator));

            if (popAuthenticatorValidationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popAuthenticatorValidationPolicy));

            popAuthenticatorValidationPolicy.AuthenticatorReplayValidator?.Invoke(jwtAuthenticator);

            ValidateAuthenticatorSignature(jwtAuthenticator, validatedToken, popAuthenticatorValidationPolicy);

            if (popAuthenticatorValidationPolicy.ValidateTs)
                ValidateTsClaim(jwtAuthenticator, popAuthenticatorValidationPolicy);

            if (popAuthenticatorValidationPolicy.ValidateM)
                ValidateMClaim(jwtAuthenticator, httpRequestData?.HttpMethod);

            if (popAuthenticatorValidationPolicy.ValidateU)
                ValidateUClaim(jwtAuthenticator, httpRequestData?.HttpRequestUri, popAuthenticatorValidationPolicy);

            if (popAuthenticatorValidationPolicy.ValidateP)
                ValidatePClaim(jwtAuthenticator, httpRequestData?.HttpRequestUri, popAuthenticatorValidationPolicy);

            if (popAuthenticatorValidationPolicy.ValidateQ)
                ValidateQClaim(jwtAuthenticator, httpRequestData?.HttpRequestUri, popAuthenticatorValidationPolicy);

            if (popAuthenticatorValidationPolicy.ValidateH)
                ValidateHClaim(jwtAuthenticator, httpRequestData?.HttpRequestHeaders, popAuthenticatorValidationPolicy);

            if (popAuthenticatorValidationPolicy.ValidateB)
                ValidateBClaim(jwtAuthenticator, httpRequestData?.HttpRequestBody, popAuthenticatorValidationPolicy);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtAuthenticator"></param>
        /// <param name="validatedToken"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        protected virtual void ValidateAuthenticatorSignature(JsonWebToken jwtAuthenticator, JsonWebToken validatedToken, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy)
        {
            if (jwtAuthenticator == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtAuthenticator));

            var popKey = ResolvePopKey(validatedToken, popAuthenticatorValidationPolicy);

            if (!jwtAuthenticator.TryGetHeaderValue(JwtHeaderParameterNames.Alg, out string algorithm))
            {
                throw new PopProtocolException("TODO");
            }
            else
            {
                var signatureProvider = popKey.CryptoProviderFactory.CreateForVerifying(popKey, algorithm);

                if (!signatureProvider.Verify(
                 Encoding.UTF8.GetBytes(jwtAuthenticator.EncodedHeader + "." + jwtAuthenticator.EncodedPayload),
                 Base64UrlEncoder.DecodeBytes(jwtAuthenticator.EncodedSignature)))
                    throw new PopProtocolException("TODO");
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
                throw new PopProtocolException("TODO");

            DateTime utcNow = DateTime.UtcNow;
            DateTime authenticatorExpirationTime = EpochTime.DateTime(tsClaimValue);

            if (authenticatorExpirationTime > DateTimeUtil.Add(utcNow, popAuthenticatorValidationPolicy.ClockSkew))
                throw new PopProtocolException("TODO");
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
                throw new PopProtocolException("TODO");

            if (!jwtAuthenticator.TryGetPayloadValue(PopConstants.ClaimTypes.M, out string httpMethod))
                throw new PopProtocolException("TODO");

            if (!string.Equals(expectedHttpMethod, httpMethod, StringComparison.Ordinal))
            {
                throw new PopProtocolException("TODO");
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtAuthenticator"></param>
        /// <param name="httpRequestUri"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        protected virtual void ValidateUClaim(JsonWebToken jwtAuthenticator, Uri httpRequestUri, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy)
        {
            if (jwtAuthenticator == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtAuthenticator));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestUri));

            if (popAuthenticatorValidationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popAuthenticatorValidationPolicy));

            if (!httpRequestUri.IsAbsoluteUri)
                throw new PopProtocolException("TODO");

            if (!jwtAuthenticator.TryGetPayloadValue(PopConstants.ClaimTypes.U, out string uClaimValue))
                throw new PopProtocolException("TODO");

            var expectedUClaimValue = httpRequestUri.Host;
            var expectedUClaimValueIncludingPort = $"{expectedUClaimValue}:{httpRequestUri.Port}";

            if (!string.Equals(expectedUClaimValue, uClaimValue, StringComparison.Ordinal) &&
                !string.Equals(expectedUClaimValueIncludingPort, uClaimValue, StringComparison.Ordinal))
                throw new PopProtocolException("TODO");
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtAuthenticator"></param>
        /// <param name="httpRequestUri"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        protected virtual void ValidatePClaim(JsonWebToken jwtAuthenticator, Uri httpRequestUri, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy)
        {
            if (jwtAuthenticator == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtAuthenticator));

            if (httpRequestUri == null)
                throw new PopProtocolException("TODO");

            if (popAuthenticatorValidationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popAuthenticatorValidationPolicy));

            if (!httpRequestUri.IsAbsoluteUri)
            {
                if (!Uri.TryCreate(_baseUriHelper, httpRequestUri, out httpRequestUri))
                    throw new PopProtocolException("TODO");
            }

            if (!jwtAuthenticator.TryGetPayloadValue(PopConstants.ClaimTypes.P, out string pClaimValue))
                throw new PopProtocolException("TODO");

            var expectedPClaimValue = httpRequestUri.AbsolutePath.TrimEnd('/');

            if (!string.Equals(expectedPClaimValue, pClaimValue, StringComparison.Ordinal))
                throw new PopProtocolException("TODO");
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtAuthenticator"></param>
        /// <param name="httpRequestUri"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        protected virtual void ValidateQClaim(JsonWebToken jwtAuthenticator, Uri httpRequestUri, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtAuthenticator"></param>
        /// <param name="httpRequestHeaders"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        protected virtual void ValidateHClaim(JsonWebToken jwtAuthenticator, IEnumerable<KeyValuePair<string, IEnumerable<string>>> httpRequestHeaders, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwtAuthenticator"></param>
        /// <param name="httpRequestBody"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        protected virtual void ValidateBClaim(JsonWebToken jwtAuthenticator, byte[] httpRequestBody, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="accessToken"></param>
        /// <param name="tokenValidationParameters"></param>
        /// <returns></returns>
        protected virtual SecurityToken ValidateToken(string accessToken, TokenValidationParameters tokenValidationParameters)
        {
            if (string.IsNullOrEmpty(accessToken))
                throw LogHelper.LogArgumentNullException(nameof(accessToken));

            if (tokenValidationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(tokenValidationParameters));

            var tokenValidationResult = _handler.ValidateToken(accessToken, tokenValidationParameters);

            if (!tokenValidationResult.IsValid)
            {
                throw LogHelper.LogExceptionMessage(tokenValidationResult.Exception);
            }

            return tokenValidationResult.SecurityToken;
        }

        #region Resolving PoP key
        /// <summary>
        /// 
        /// </summary>
        /// <param name="validatedToken"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        /// <returns></returns>
        protected virtual SecurityKey ResolvePopKey(JsonWebToken validatedToken, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy)
        {
            if (validatedToken == null)
                throw LogHelper.LogArgumentNullException(nameof(validatedToken));

            if (popAuthenticatorValidationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popAuthenticatorValidationPolicy));

            if (popAuthenticatorValidationPolicy.PopKeyResolver != null)
            {
                return popAuthenticatorValidationPolicy.PopKeyResolver(validatedToken, popAuthenticatorValidationPolicy);
            }

            if (!validatedToken.TryGetPayloadValue(PopConstants.ClaimTypes.Cnf, out JObject cnf))
                throw new PopProtocolException("TODO");

            if (cnf.TryGetValue(JwtHeaderParameterNames.Jwk, StringComparison.Ordinal, out var jwk))
            {
                return ResolvePopKeyFromJwk(jwk.ToString());
            }
            else if (cnf.TryGetValue(PopConstants.ClaimTypes.Jwe, StringComparison.Ordinal, out var jwe))
            {
                return ResolvePopKeyFromJwe(jwe.ToString(), popAuthenticatorValidationPolicy);
            }
            else if (cnf.TryGetValue(JwtHeaderParameterNames.Jku, StringComparison.Ordinal, out var jku))
            {
                if (cnf.TryGetValue(JwtHeaderParameterNames.Kid, StringComparison.Ordinal, out var kid))
                    return ResolvePopKeyFromJku(jku.ToString(), kid.ToString(), popAuthenticatorValidationPolicy);
                else
                    return ResolvePopKeyFromJku(jku.ToString(), popAuthenticatorValidationPolicy);
            }
            else if (cnf.TryGetValue(JwtHeaderParameterNames.Kid, StringComparison.Ordinal, out var kid))
            {
                return ResolvePopKeyFromKid(kid.ToString(), popAuthenticatorValidationPolicy);
            }
            else
                throw new PopProtocolException("TODO");
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
                    throw new PopProtocolException("TODO");
            }
            else
                throw new PopProtocolException("TODO");
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwe"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        /// <returns></returns>
        protected virtual SecurityKey ResolvePopKeyFromJwe(string jwe, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy)
        {
            if (string.IsNullOrEmpty(jwe))
                throw LogHelper.LogArgumentNullException(nameof(jwe));

            if (popAuthenticatorValidationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popAuthenticatorValidationPolicy));

            var jsonWebToken = _handler.ReadJsonWebToken(jwe);

            IEnumerable<SecurityKey> decryptionKeys;
            if (popAuthenticatorValidationPolicy.CnfDecryptionKeysResolver != null)
                decryptionKeys = popAuthenticatorValidationPolicy.CnfDecryptionKeysResolver(jsonWebToken);
            else
                decryptionKeys = popAuthenticatorValidationPolicy.CnfDecryptionKeys;

            if (decryptionKeys == null || !decryptionKeys.Any())
                throw new PopProtocolException("TODO");

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
            catch (Exception)
            {
                throw new PopProtocolException("TODO");
            }

            if (JsonWebKeyConverter.TryConvertToSymmetricSecurityKey(jsonWebKey, out var symmetricKey))
                return symmetricKey;
            else
                throw new PopProtocolException("TODO");
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jku"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        /// <returns></returns>
        protected virtual SecurityKey ResolvePopKeyFromJku(string jku, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy)
        {
            var popKeys = GetPopKeys(jku, popAuthenticatorValidationPolicy);
            var popKeyCount = popKeys.Count;

            if (popKeyCount == 0)
                throw new PopProtocolException("TODO");
            else if (popKeyCount > 1)
                throw new PopProtocolException("TODO");
            else
                return popKeys[0];
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jku"></param>
        /// <param name="kid"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        /// <returns></returns>
        protected virtual SecurityKey ResolvePopKeyFromJku(string jku, string kid, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy)
        {
            if (string.IsNullOrEmpty(kid))
                throw LogHelper.LogArgumentNullException(nameof(kid));

            var popKeys = GetPopKeys(jku, popAuthenticatorValidationPolicy);
            foreach (var key in popKeys)
            {
                if (string.Equals(key.KeyId, kid.ToString(), StringComparison.Ordinal))
                    return key;
            }

            throw new PopProtocolException();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jkuSetUrl"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        /// <returns></returns>
        protected virtual IList<SecurityKey> GetPopKeys(string jkuSetUrl, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy)
        {
            if (string.IsNullOrEmpty(jkuSetUrl))
                throw LogHelper.LogArgumentNullException(nameof(jkuSetUrl));

            if (popAuthenticatorValidationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popAuthenticatorValidationPolicy));

            try
            {
                var httpClient = popAuthenticatorValidationPolicy.HttpClientForJkuResourceRetrieval ?? _defaultHttpClient;

                if (!Utility.IsHttps(jkuSetUrl) && popAuthenticatorValidationPolicy.RequireHttpsForJkuResourceRetrieval)
                    throw LogHelper.LogExceptionMessage(new PopProtocolException(LogHelper.FormatInvariant(LogMessages.IDX23006, jkuSetUrl)));

                var response = httpClient.GetAsync(jkuSetUrl).ConfigureAwait(false).GetAwaiter().GetResult();
                var jsonWebKey = response.Content.ReadAsStringAsync().ConfigureAwait(false).GetAwaiter().GetResult();
                var jsonWebKeySet = new JsonWebKeySet(jsonWebKey);
                return jsonWebKeySet.GetSigningKeys();
            }
            catch
            {
                throw new PopProtocolException();
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="kid"></param>
        /// <param name="popAuthenticatorValidationPolicy"></param>
        /// <returns></returns>
        protected virtual SecurityKey ResolvePopKeyFromKid(string kid, PopAuthenticatorValidationPolicy popAuthenticatorValidationPolicy)
        {
            if (string.IsNullOrEmpty(kid))
                throw LogHelper.LogArgumentNullException(nameof(kid));

            if (popAuthenticatorValidationPolicy == null)
                throw LogHelper.LogArgumentNullException(nameof(popAuthenticatorValidationPolicy));

            if (popAuthenticatorValidationPolicy.PopKeyIdentifier != null)
                return popAuthenticatorValidationPolicy.PopKeyIdentifier(kid.ToString());
            else
            {
                throw new PopProtocolException("TODO");
            }
        }
        #endregion
    }
}
