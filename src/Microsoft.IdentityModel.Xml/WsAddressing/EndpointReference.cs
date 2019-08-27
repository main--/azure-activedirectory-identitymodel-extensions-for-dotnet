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
using System.Collections.ObjectModel;
using System.Xml;
using Microsoft.IdentityModel.Logging;

#pragma warning disable 1591
namespace Microsoft.IdentityModel.WsAddressing
{
    public class EndpointReference
    {
        public EndpointReference(string uri)
        {
            if (uri == null)
                throw LogHelper.LogArgumentNullException(nameof(uri));

            if (!Uri.IsWellFormedUriString(uri, UriKind.Absolute))
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant($"uri is not absolute: {uri}")));
                
            Uri = new Uri(uri);
            AdditionalXmlElements = new Collection<XmlElement>();
        }

        public readonly ICollection<XmlElement> AdditionalXmlElements;

        public readonly Uri Uri;

        public void WriteTo(XmlWriter writer)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            writer.WriteStartElement(WsAddressing10Constants.Prefix, WsAddressingConstants.Elements.EndpointReference, WsAddressing10Constants.Namespace);
            writer.WriteStartElement(WsAddressing10Constants.Prefix, WsAddressingConstants.Elements.Address, WsAddressing10Constants.Namespace);
            writer.WriteString(Uri.AbsoluteUri);
            writer.WriteEndElement();
            writer.WriteEndElement();
        }

        /// <summary>
        /// Reads an <see cref="EndpointReference"/> from xml reader.
        /// </summary>
        /// <param name="reader">The xml reader.</param>
        /// <returns>An <see cref="EndpointReference"/> instance.</returns>
        public static EndpointReference ReadFrom(XmlReader reader)
        {
            return ReadFrom(XmlDictionaryReader.CreateDictionaryReader(reader));
        }

        /// <summary>
        /// Reads an <see cref="EndpointReference"/>
        /// </summary>
        /// <param name="reader">The xml dictionary reader.</param>
        /// <returns>An <see cref="EndpointReference"/> instance.</returns>
        public static EndpointReference ReadFrom(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            reader.ReadFullStartElement();
            reader.MoveToContent();

            if (reader.IsNamespaceUri(WsAddressing10Constants.Namespace) || reader.IsNamespaceUri(WsAddressing200408Constants.Namespace))
            {
                if (reader.IsStartElement(WsAddressingConstants.Elements.Address, WsAddressing10Constants.Namespace) ||
                    reader.IsStartElement(WsAddressingConstants.Elements.Address, WsAddressing200408Constants.Namespace))
                {
                    var endpointReference = new EndpointReference(reader.ReadElementContentAsString());
                    while ( reader.IsStartElement() )
                    {
                        bool emptyElement = reader.IsEmptyElement;                       
                        XmlReader subtreeReader = reader.ReadSubtree();
                        XmlDocument doc = new XmlDocument();
                        doc.PreserveWhitespace = true;
                        doc.Load( subtreeReader );
                        endpointReference.AdditionalXmlElements.Add( doc.DocumentElement );
                        if ( !emptyElement )
                            reader.ReadEndElement();
                    }

                    reader.ReadEndElement();
                    return endpointReference;
                }
            }

            return null;
        }
    }
}
