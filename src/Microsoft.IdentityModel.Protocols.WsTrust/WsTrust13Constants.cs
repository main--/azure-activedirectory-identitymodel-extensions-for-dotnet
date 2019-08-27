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
    /// Constants for WsTrust13.
    /// Attributes and Elements are almost the same across all versions 2005, 1.3, 1.4
    /// </summary>
    public static class WsTrust13Constants
    {

#pragma warning disable 1591

        public const string Prefix = "trust";
        public const string Namespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
        public const string SchemaLocation = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3.xsd";

        public const string Schema = @"<?xml version='1.0' encoding='utf-8'?>
<xs:schema xmlns:xs='http://www.w3.org/2001/XMLSchema'
           xmlns:trust='http://docs.oasis-open.org/ws-sx/ws-trust/200512'
           targetNamespace='http://docs.oasis-open.org/ws-sx/ws-trust/200512'
           elementFormDefault='qualified' >

<xs:element name='RequestSecurityToken' type='trust:RequestSecurityTokenType' />
  <xs:complexType name='RequestSecurityTokenType' >
    <xs:choice minOccurs='0' maxOccurs='unbounded' >
        <xs:any namespace='##any' processContents='lax' minOccurs='0' maxOccurs='unbounded' />
    </xs:choice>
    <xs:attribute name='Context' type='xs:anyURI' use='optional' />
    <xs:anyAttribute namespace='##other' processContents='lax' />
  </xs:complexType>

<xs:element name='RequestSecurityTokenResponse' type='trust:RequestSecurityTokenResponseType' />
  <xs:complexType name='RequestSecurityTokenResponseType' >
    <xs:choice minOccurs='0' maxOccurs='unbounded' >
        <xs:any namespace='##any' processContents='lax' minOccurs='0' maxOccurs='unbounded' />
    </xs:choice>
    <xs:attribute name='Context' type='xs:anyURI' use='optional' />
    <xs:anyAttribute namespace='##other' processContents='lax' />
  </xs:complexType>

  <xs:element name='RequestSecurityTokenResponseCollection' type='trust:RequestSecurityTokenResponseCollectionType' />
  <xs:complexType name='RequestSecurityTokenResponseCollectionType' >
    <xs:sequence>
      <xs:element ref='trust:RequestSecurityTokenResponse' minOccurs='1' maxOccurs='unbounded' />
    </xs:sequence>
    <xs:anyAttribute namespace='##other' processContents='lax' />
  </xs:complexType>

        </xs:schema>";

        public static class RequestTypes
        {
            public const string Issue = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue";
            public const string RSTIssue = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue";
            public const string RSTRIssue = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Issue";
            public const string RSTRCIssueFinal = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTRC/IssueFinal";

            public const string Renew = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Renew";
            public const string RSTRenew = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Renew";
            public const string RSTRRenew = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Renew";
            public const string RSTRRenewFinal = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/RenewFinal";

            public const string Cancel = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Cancel";
            public const string RSTCancel = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Cancel";
            public const string RSTRCancel = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Cancel";
            public const string RSTRCancelFinal = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/CancelFinal";

            public const string Validate = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Validate";
            public const string RSTValidate = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Validate";
            public const string RSTRValidate = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Validate";
            public const string RSTRValidateFinal = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/ValidateFinal";

            public const string RSTSStatus = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Status";
        }
    }
}
 
