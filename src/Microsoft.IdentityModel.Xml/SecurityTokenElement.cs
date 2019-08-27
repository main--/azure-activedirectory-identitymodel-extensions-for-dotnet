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

using System.Collections.Generic;
using System.Xml;
using Microsoft.IdentityModel.Tokens;
using static Microsoft.IdentityModel.Logging.LogHelper;

#pragma warning disable 1591

namespace Microsoft.IdentityModel.Xml
{
    public class SecurityTokenElement
    {
        /// <summary>
        /// Creates an instance of this object using a <see cref="SecurityToken"/> object.
        /// </summary>
        /// <param name="securityToken">The security token this object represents.</param>
        /// <remarks>
        /// </remarks>
        public SecurityTokenElement(SecurityToken securityToken)
        {
            SecurityToken = securityToken ?? throw LogArgumentNullException(nameof(securityToken));
        }

        /// <summary>
        /// Creates an instance of this object using XML representation of the security token.
        /// </summary>
        /// <param name="securityTokenXml">The <see cref="XmlElement"/> representation of the security token.</param>
        /// <param name="securityTokenHandlers">The collection of <see cref="SecurityTokenHandler"/> objects that may 
        /// be used to read and validate the security token this object represents.</param>
        public SecurityTokenElement(XmlElement securityTokenXml, IEnumerable<SecurityTokenHandler> securityTokenHandlers)
        {
            SecurityTokenXml = securityTokenXml ?? throw LogArgumentNullException(nameof(securityTokenXml));
            SecurityTokenHandlers = securityTokenHandlers ?? throw LogArgumentNullException(nameof(securityTokenHandlers));
        }

        public SecurityToken SecurityToken { get; }

        public XmlElement SecurityTokenXml { get; }

        public IEnumerable<SecurityTokenHandler> SecurityTokenHandlers { get; }
    }
#pragma warning restore 1591
}
