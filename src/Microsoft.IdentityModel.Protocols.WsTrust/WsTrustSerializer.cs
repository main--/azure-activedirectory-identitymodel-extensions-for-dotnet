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

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.WsAddressing;
using Microsoft.IdentityModel.WsPolicy;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
#pragma warning disable 1591
    /// <summary>
    /// Base class for support of versions of WS-Trust request messages.
    /// </summary>
    public class WsTrustSerializer
    {
        public WsTrustSerializer()
        {
        }

        /// <summary>
        /// When overriden in the derived class deserializes the RST from the XmlReader to a RequestSecurityToken object.
        /// </summary>
        /// <param name="reader">XML reader over the RST</param>
        /// <returns>RequestSecurityToken object if the deserialization was successful</returns>
        public WsTrustResponse ReadXml(XmlReader reader)
        {
            return null;
        }

        /// <summary>
        /// When overriden in the derived class serializes the given RequestSecurityToken into the XmlWriter
        /// </summary>
        /// <param name="writer">XML writer to serialize into</param>
        /// <param name="request">RequestSecurityToken object to be serialized</param>
        public void WriteXml(XmlWriter writer, WsTrustRequest request)
        {
            var serializationContext = new WsTrustSerializationContext(request.WsTrustVersion);

            writer.WriteStartElement(WsTrust13Constants.Prefix, WsTrustConstants.Elements.RequestSecurityToken, WsTrust13Constants.Namespace);

            if (!string.IsNullOrEmpty(request.Context))
                writer.WriteAttributeString(WsTrustConstants.Attributes.Context, request.Context);

            // TODO - assuming Issue

            writer.WriteStartElement(serializationContext.Prefix, WsTrustConstants.Elements.RequestType, serializationContext.Namespace);
            writer.WriteString(serializationContext.Issue);
            writer.WriteEndElement();

            if (request.AppliesTo != null)
                WriteAppliesTo(writer, request, serializationContext);

            #region hidden
            /*
                        if (rst.Claims.Count > 0)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.Claims, rst.Claims, rst, context);
                        }

                        if (!string.IsNullOrEmpty(rst.ComputedKeyAlgorithm))
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.ComputedKeyAlgorithm, rst.ComputedKeyAlgorithm, rst, context);
                        }

                        if (!string.IsNullOrEmpty(rst.SignWith))
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.SignWith, rst.SignWith, rst, context);
                        }

                        if (!string.IsNullOrEmpty(rst.EncryptWith))
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.EncryptWith, rst.EncryptWith, rst, context);
                        }

                        if (rst.Entropy != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.Entropy, rst.Entropy, rst, context);
                        }

                        if (rst.KeySizeInBits.HasValue)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.KeySize, rst.KeySizeInBits, rst, context);
                        }

                        if (!string.IsNullOrEmpty(rst.KeyType))
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.KeyType, rst.KeyType, rst, context);
                        }

                        if (rst.Lifetime != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.Lifetime, rst.Lifetime, rst, context);
                        }

                        if (rst.RenewTarget != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.RenewTarget, rst.RenewTarget, rst, context);
                        }

                        if (rst.OnBehalfOf != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.OnBehalfOf, rst.OnBehalfOf, rst, context);
                        }

                        if (rst.ActAs != null)
                        {
                            requestSerializer.WriteXmlElement(writer, WSTrust14Constants.ElementNames.ActAs, rst.ActAs, rst, context);
                        }

                        if (!string.IsNullOrEmpty(rst.RequestType))
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.RequestType, rst.RequestType, rst, context);
                        }

                        if (!string.IsNullOrEmpty(rst.TokenType))
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.TokenType, rst.TokenType, rst, context);
                        }

                        if (rst.UseKey != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.UseKey, rst.UseKey, rst, context);
                        }

                        if (!string.IsNullOrEmpty(rst.AuthenticationType))
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.AuthenticationType, rst.AuthenticationType, rst, context);
                        }

                        if (!string.IsNullOrEmpty(rst.EncryptionAlgorithm))
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.EncryptionAlgorithm, rst.EncryptionAlgorithm, rst, context);
                        }

                        if (!string.IsNullOrEmpty(rst.CanonicalizationAlgorithm))
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.CanonicalizationAlgorithm, rst.CanonicalizationAlgorithm, rst, context);
                        }

                        if (!string.IsNullOrEmpty(rst.SignatureAlgorithm))
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.SignatureAlgorithm, rst.SignatureAlgorithm, rst, context);
                        }

                        if (rst.BinaryExchange != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.BinaryExchange, rst.BinaryExchange, rst, context);
                        }

                        if (rst.Issuer != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.Issuer, rst.Issuer, rst, context);
                        }

                        if (rst.ProofEncryption != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.ProofEncryption, rst.ProofEncryption, rst, context);
                        }

                        if (rst.Encryption != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.Encryption, rst.Encryption, rst, context);
                        }

                        if (rst.DelegateTo != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.DelegateTo, rst.DelegateTo, rst, context);
                        }

                        if (rst.Forwardable != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.Forwardable, rst.Forwardable.Value, rst, context);
                        }

                        if (rst.Delegatable != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.Delegatable, rst.Delegatable.Value, rst, context);
                        }

                        if (rst.AllowPostdating)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.AllowPostdating, rst.AllowPostdating, rst, context);
                        }

                        if (rst.Renewing != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.Renewing, rst.Renewing, rst, context);
                        }

                        if (rst.CancelTarget != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.CancelTarget, rst.CancelTarget, rst, context);
                        }

                        if ((rst.Participants != null) && ((rst.Participants.Primary != null) || (rst.Participants.Participant.Count > 0)))
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.Participants, rst.Participants, rst, context);
                        }

                        if (rst.AdditionalContext != null)
                        {
                            requestSerializer.WriteXmlElement(writer, WSAuthorizationConstants.Elements.AdditionalContext, rst.AdditionalContext, rst, context);
                        }

                        requestSerializer.WriteKnownRequestElement(rst, writer, context);

                        // Step 5: Write the custom elements here from the Elements bag
                        foreach (KeyValuePair<string, object> messageParam in rst.Properties)
                        {
                            requestSerializer.WriteXmlElement(writer, messageParam.Key, messageParam.Value, rst, context);
                        }
                        */
            #endregion hidden

            // Step 6: close the RST element
            writer.WriteEndElement();
        }

        protected virtual void WriteAppliesTo(XmlWriter writer, WsTrustRequest request, WsTrustSerializationContext serializationContext)
        {
            writer.WriteStartElement(WsPolicy12Constants.Elements.AppliesTo, WsPolicy12Constants.Namespace);
            writer.WriteStartElement(WsAddressing10Constants.Prefix, WsAddressingConstants.Elements.EndpointReference, WsAddressing10Constants.Namespace);
            writer.WriteStartElement(WsAddressing10Constants.Prefix, WsAddressingConstants.Elements.Address, WsAddressing10Constants.Namespace);
            writer.WriteString(request.AppliesTo.Uri.AbsoluteUri);
            writer.WriteEndElement();
            foreach (XmlElement element in request.AppliesTo.AdditionalXmlElements)
                element.WriteTo(writer);

            writer.WriteEndElement();
            writer.WriteEndElement();
        }

        /// <summary>
        /// Reads the 'RequestedSecurityToken' element.
        /// </summary>
        /// <returns>the 'SecurityToken'.</returns>
        protected virtual RequestedSecurityToken ReadRequestedSecurityToken(XmlDictionaryReader xmlReader)
        {

            if (!XmlUtil.IsStartElement(xmlReader, WsTrustConstants.Elements.RequestedSecurityToken, WsTrustNamespaceList))
                throw LogReadException("Message");

            xmlReader.ReadStartElement();
            xmlReader.MoveToContent();

            RequestedSecurityToken requestedSecurityToken = null;
            using (var ms = new MemoryStream())
            {
                using (var writer = XmlDictionaryWriter.CreateTextWriter(ms, Encoding.UTF8, false))
                {
                    writer.WriteNode(xmlReader, true);
                    writer.Flush();
                }
                ms.Seek(0, SeekOrigin.Begin);
                var tokenBytes = ms.ToArray();
                var token = Encoding.UTF8.GetString(tokenBytes);
                requestedSecurityToken = new RequestedSecurityToken { Token = token };
            }

            // </RequestedSecurityToken>
            xmlReader.ReadEndElement();

            return requestedSecurityToken;
        }

        internal static List<string> WsTrustNamespaceList = new List<string>() { WsTrust2005Constants.Namespace, WsTrust13Constants.Namespace, WsTrust14Constants.Namespace };
        internal static List<string> WsTrustNamespaceNon2005List = new List<string>() { WsTrust13Constants.Namespace, WsTrust14Constants.Namespace };

        internal static Exception LogReadException(string format, params object[] args)
        {
            return LogHelper.LogExceptionMessage(new WsTrustReadException(LogHelper.FormatInvariant(format, args)));
        }

        internal static Exception LogReadException(string format, Exception inner, params object[] args)
        {
            return LogHelper.LogExceptionMessage(new WsTrustReadException(LogHelper.FormatInvariant(format, args), inner));
        }

        internal static Exception LogWriteException(string format, params object[] args)
        {
            return LogHelper.LogExceptionMessage(new WsTrustWriteException(LogHelper.FormatInvariant(format, args)));
        }

        internal static Exception LogWriteException(string format, Exception inner, params object[] args)
        {
            return LogHelper.LogExceptionMessage(new WsTrustWriteException(LogHelper.FormatInvariant(format, args), inner));
        }
    }
}
