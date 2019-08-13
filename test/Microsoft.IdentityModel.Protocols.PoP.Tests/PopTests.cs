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
//------------------------------------------------------------------------------

using Microsoft.IdentityModel.Tokens;
using System;
using Xunit;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Net.Http;

namespace Microsoft.IdentityModel.Protocols.PoP.Tests
{
    public class PopTests
    {
        [Fact]
        public void MsalUsageSample()
        {
            IPopAuthenticatorCreator httpAuthenticatorCreator = new PopAuthenticationHandler();

            string popToken = "{obtain a token that posses a PoP key}";
            var popPrivateKey = new RsaSecurityKey(new RSACryptoServiceProvider(2048)) { KeyId = Guid.NewGuid().ToString() }; // set a key which public parts are used to create a pop token.
            SigningCredentials signingCredentials = new SigningCredentials(popPrivateKey, SecurityAlgorithms.RsaSha256); // set the key and the algorithm

            // adjust the httpAuthenticatorCreationPolicy
            var popAuthenticatorCreationParameters = new PopAuthenticatorCreationParameters()
            {
                HttpMethod = "GET",
                HttpRequestUri = new Uri("https://www.contoso.com:443/it/requests?b=bar&a=foo&c=duck"),
                HttpRequestBody = Guid.NewGuid().ToByteArray(),
                HttpRequestHeaders = new Dictionary<string, string>() { { "Content-Type", "application/json" }, { "Etag", "742-3u8f34-3r2nvv3" } },
                CreateTs = true,
                CreateM = true,
                CreateP = true,
                CreateU = true,
                CreateH = true,
                CreateB = true,
                CreateQ = true,
            };

            try
            {
                var authenticator = httpAuthenticatorCreator.CreatePopAuthenticator(popToken, signingCredentials, popAuthenticatorCreationParameters);

                //4.1. 
                var popHeader = PopUtilities.CreatePopHeader(authenticator);
            }
            catch (PopProtocolException e)
            {
                // handle the exception
                throw e;
            }
            catch (Exception ex)
            {
                // handle the exception
                throw ex;
            }
        }
    }
}
