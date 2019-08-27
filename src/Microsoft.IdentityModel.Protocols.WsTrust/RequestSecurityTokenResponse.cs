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
using Microsoft.IdentityModel.WsAddressing;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// The Entropy used in both token request message and token response message. 
    /// </summary>
    public class RequestSecurityTokenResponse
    {
        private EndpointReference _appliesTo;
        private string _context;
        private Entropy _entropy;
        private Lifetime _lifetime;
        private string _tokenType;
     
        /// <summary>
        /// 
        /// </summary>
        public RequestSecurityTokenResponse()
        {
        }

        /// <summary>
        /// Gets or sets this optional element that specifies the endpoint address for which this security token is desired.
        /// For example, the service to which this token applies.
        /// </summary>
        /// <remarks>
        /// Either TokenType or AppliesTo SHOULD be defined in the token request message. If both 
        /// are specified, the AppliesTo field takes precedence.
        /// </remarks>
        public EndpointReference AppliesTo
        {
            get => _appliesTo;
            set => _appliesTo = value ?? throw LogHelper.LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets or sets the optional context element specifies an identifier/context for this request.
        /// **
        /// </summary>
        /// <remarks>
        /// All subsequent RSTR elements relating to this request MUST carry this attribute.
        /// </remarks>
        public string Context
        {
            get => _context;
            set => _context = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(value)) : value;
        }


        /// <summary>
        /// Gets or sets entropy to send
        /// </summary>
        public Entropy Entropy
        {
            get => _entropy;
            set => _entropy = value ?? throw LogHelper.LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets or sets the Lifetime.
        /// </summary>
        public Lifetime Lifetime
        {
            get => _lifetime;
            set => _lifetime = value ?? throw LogHelper.LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// 
        /// </summary>
        public RequestedSecurityToken RequestedSecurityToken{ get; set; }

        /// <summary>
        /// 
        /// </summary>
        public RequestedProofToken RequestedProofToken { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public SecurityTokenElement RequestedAttachedReference { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public SecurityTokenElement RequestedUnattachedReference { get; set; }

        /// <summary>
        /// Gets or sets the TokenType.
        /// </summary>
        public string TokenType
        {
            get => _tokenType;
            set => _tokenType = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(value)) : value;
        }
    }
}
