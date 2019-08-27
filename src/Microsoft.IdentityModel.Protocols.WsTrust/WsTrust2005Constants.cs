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

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Constants for WsTrust2005.
    /// </summary>
    public static class WsTrust2005Constants
    {
#pragma warning disable 1591
        public const string Namespace = "http://schemas.xmlsoap.org/ws/2005/02/trust";
        public const string Prefix = "t";
        public const string SchemaLocation = "http://schemas.xmlsoap.org/ws/2005/02/trust/ws-trust.xsd";

        public const string Schema = @"<?xml version='1.0' encoding='utf-8'?>
<xs:schema xmlns:xs='http://www.w3.org/2001/XMLSchema'
           xmlns:wst='http://schemas.xmlsoap.org/ws/2005/02/trust'
           targetNamespace='http://schemas.xmlsoap.org/ws/2005/02/trust'
           elementFormDefault='qualified' >

<xs:element name='RequestSecurityToken' type='wst:RequestSecurityTokenType' />
  <xs:complexType name='RequestSecurityTokenType' >
    <xs:choice minOccurs='0' maxOccurs='unbounded' >
        <xs:any namespace='##any' processContents='lax' minOccurs='0' maxOccurs='unbounded' />
    </xs:choice>
    <xs:attribute name='Context' type='xs:anyURI' use='optional' />
    <xs:anyAttribute namespace='##other' processContents='lax' />
  </xs:complexType>

<xs:element name='RequestSecurityTokenResponse' type='wst:RequestSecurityTokenResponseType' />
  <xs:complexType name='RequestSecurityTokenResponseType' >
    <xs:choice minOccurs='0' maxOccurs='unbounded' >
        <xs:any namespace='##any' processContents='lax' minOccurs='0' maxOccurs='unbounded' />
    </xs:choice>
    <xs:attribute name='Context' type='xs:anyURI' use='optional' />
    <xs:anyAttribute namespace='##other' processContents='lax' />
  </xs:complexType>

        </xs:schema>";

        public static class RequestTypes
        {
            public const string Issue = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue";
            public const string IssueResponse = "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue";

            public const string Renew = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Renew";
            public const string RenewResponse = "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Renew";

            public const string Validate = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Validate";
            public const string ValidateResponse = "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Validate";

            public const string Cancel = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Cancel";
            public const string CancelResponse = "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Cancel";

            public const string RequestSecurityContextToken = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT";
            public const string RequestSecurityContextTokenResponse = "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT";

            public const string RequestSecurityContextTokenCancel = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT-Cancel";
            public const string RequestSecurityContextTokenResponseCancel = "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT-Cancel";
        }
    }
}
 
