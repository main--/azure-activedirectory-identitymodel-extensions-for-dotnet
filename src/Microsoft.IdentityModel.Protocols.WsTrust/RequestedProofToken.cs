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

using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// The content of a RequestedProofToken element could be EncryptedSecurityToken which means that EncryptedKey is used 
    /// under the RequestedProofToken. If the security token is a regular token, such as a SCT,
    /// then its session key will be the material which gets encrypted.  Another possibility is where
    /// we use combined entropy, then RequestedProofToken will only contain a ComputedKey element.
    /// </summary>
    public class RequestedProofToken
    {
        /// <summary>
        /// In case of combined entropy, construct a requestedprooftoken 
        /// instance with computed key algorithm to specify the algorithm used to 
        /// calculate the session key.
        /// </summary>
        /// <param name="computedKeyAlgorithm">The algorithm used to computed the session key in 
        /// the combined entropy case.</param>
        public RequestedProofToken(string computedKeyAlgorithm)
        {
            ComputedKeyAlgorithm =  (string.IsNullOrEmpty(computedKeyAlgorithm)) ? throw LogHelper.LogArgumentNullException(nameof(computedKeyAlgorithm)) : computedKeyAlgorithm;
        }

        /// <summary>
        /// Constructs a requested proof token instance with the protected key.
        /// </summary>
        /// <param name="protectedKey">The protected key which can be either binary secret or encrypted key.</param>
        public RequestedProofToken(ProtectedKey protectedKey)
        {

            ProtectedKey = protectedKey ?? throw LogHelper.LogArgumentNullException(nameof(protectedKey));
        }

        /// <summary>
        /// Gets the computed key algorithm used to calculate the session key in the combined 
        /// entropy case.
        /// </summary>
        public string ComputedKeyAlgorithm { get; }

        /// <summary>
        /// In the case when the requested proof token contains the real key, 
        /// ProtectedKey getter will returns the real key bytes either encrypted
        /// or plaintext.
        /// </summary>
        public ProtectedKey ProtectedKey { get; }
    }
}
