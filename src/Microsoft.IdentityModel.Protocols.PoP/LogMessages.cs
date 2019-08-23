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

//  Microsoft.IdentityModel.Protocols.PoP
// Range: 23000 - 23999

namespace Microsoft.IdentityModel.Protocols.PoP
{
    /// <summary>
    /// Log messages and codes
    /// </summary>
    internal static class LogMessages
    {
        public const string IDX23000 = "IDX23000: CryptoProviderFactory.CreateForVerifying returned null for key: '{0}', signatureAlgorithm: '{1}'.";
        public const string IDX23001 = "IDX23001: HttpRequestUri must be absolute when creating the 'u' claim. HttpRequestUri: '{0}'.";
        public const string IDX23002 = "IDX23002: The HTTP Method must be uppercase HTTP verb. HttpMethod: '{0}'.";
        public const string IDX23003 = "IDX23003: The authenticator does not contain the 'at' claim. This claim is required to validate the authenticator.";
        public const string IDX23004 = "IDX23004: The following query parameters will not be included in the Q claim as they are repeated: '{0}'.";
        public const string IDX23005 = "IDX23005: The following headers will not be included in the H claim as they are repeated: '{0}'.";
        public const string IDX23006 = "IDX23006: The address specified '{0}' is not valid as per HTTPS scheme. Please specify an https address for security reasons. For testing with an http address, set the RequireHttpsForJkuResourceRetrieval property on PopAuthenticatorValidationPolicy to false.";
    }
}
