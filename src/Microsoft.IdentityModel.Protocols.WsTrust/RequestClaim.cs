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

using System.ComponentModel;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// This class is used to represent the Request Claims collection inside RequestSecurityToken.
    /// Indicate whether the claim is optional or not. 
    /// </summary>
    public class RequestClaim
    {
        /// <summary>
        /// Instantiates a required RequestClaim instance with ClaimType Uri. 
        /// </summary>
        /// <param name="claimType">ClaimType Uri attribute.</param>
        public RequestClaim(string claimType)
            : this(claimType, false)
        {
        }

        /// <summary>
        /// Instantiates a RequestClaim instance with ClaimType Uri and inidicates whether it is 
        /// optional.
        /// </summary>
        /// <param name="claimType">The ClaimType Uri attribute.</param>
        /// <param name="isOptional">The ClaimType Optional attribute.</param>
        public RequestClaim(string claimType, bool isOptional)
        {
            if (string.IsNullOrEmpty(claimType))
                throw LogHelper.LogArgumentNullException(nameof(claimType));

            ClaimType = claimType;
            IsOptional = isOptional;
        }

        /// <summary>
        /// Instantiates a RequestClaim instance with ClaimType Uri, the flag to inidicate whether it is 
        /// optional and the value of the request.
        /// </summary>
        /// <param name="claimType">The ClaimType Uri attribute.</param>
        /// <param name="isOptional">The ClaimType Optional attribute.</param>
        /// <param name="value">The actual value of the claim.</param>
        public RequestClaim(string claimType, bool isOptional, string value)
        {
            if (string.IsNullOrEmpty(claimType))
                throw LogHelper.LogArgumentNullException(nameof(claimType));

            if (string.IsNullOrEmpty(value))
                throw LogHelper.LogArgumentNullException(nameof(value));

            ClaimType = claimType;
            IsOptional = isOptional;
            Value = value;
        }

        /// <summary>
        /// Gets ClaimType uri attribute.
        /// </summary>
        public string ClaimType { get; }

        /// <summary>
        /// Gets ClaimType optional attribute.
        /// </summary>
        [DefaultValue(true)]
        public bool IsOptional { get; }

        /// <summary>
        /// Gets ClaimType value element.
        /// </summary>
        public string Value { get; }
    }
}
