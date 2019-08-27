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

#pragma warning disable 1591

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// The class defines the wst:RequestSecurityToken element which 
    /// is used to request a security token.
    /// </summary>
    public class WsTrustRequest : WsTrustMessage
    {
        /// <summary>
        /// This constructor is usually used on the sending side to instantiate a
        /// instance of RST based on the request type and its string value.
        /// </summary>
        public WsTrustRequest(string requestType)
            : this(requestType, WsTrustVersion.WsTrust13)
        {
        }

        public WsTrustRequest(string requestType, WsTrustVersion wsTrustVersion)
            : base(wsTrustVersion)
        {
            RequestType = string.IsNullOrEmpty(requestType) ? throw LogHelper.LogArgumentNullException(nameof(requestType)) : requestType;
        }

        /// <summary>
        /// Gets or sets the required element that indicates the request type.
        /// </summary>
        public string RequestType
        {
            get;
        }
    }
}
