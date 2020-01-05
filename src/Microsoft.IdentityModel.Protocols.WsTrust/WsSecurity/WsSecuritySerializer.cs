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

using System.Xml;
using Microsoft.IdentityModel.Xml;

#pragma warning disable 1591

namespace Microsoft.IdentityModel.Protocols.WsSecurity
{
    /// <summary>
    /// Base class for support of serializing versions of WS-Security.
    /// </summary>
    internal class WsSecuritySerializer
    {
        public WsSecuritySerializer()
        {
        }

        public SecurityTokenReference ReadSecurityTokenReference(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            //  <wsse:SecurityTokenReference wsu:Id="...",
            //                               wsse11:TokenType="...",
            //                               wsse:Usage="...",
            //                               wsse:Usage="...">
            //  ...
            //  </wsse:SecurityTokenReference>

            var xmlAttributes = XmlAttributeHolder.ReadAttributes(reader);
            var securityTokenReference = new SecurityTokenReference
            {
                Id = XmlAttributeHolder.GetAttribute(xmlAttributes, WsSecurityAttributes.Id, serializationContext.SecurityConstants.Namespace),
                TokenType = XmlAttributeHolder.GetAttribute(xmlAttributes, WsSecurityAttributes.TokenType, serializationContext.SecurityConstants.Namespace),
                Usage = XmlAttributeHolder.GetAttribute(xmlAttributes, WsSecurityAttributes.Usage, serializationContext.SecurityConstants.Namespace)
            };

            bool isEmptyElement = reader.IsEmptyElement;
            reader.ReadStartElement();
            if (reader.IsStartElement(WsSecurityElements.KeyIdentifier, serializationContext.SecurityConstants.Namespace))
                securityTokenReference.KeyIdentifier = ReadKeyIdentifier(reader, serializationContext);

            if (!isEmptyElement)
                reader.ReadEndElement();

            return securityTokenReference;
        }

        public KeyIdentifier ReadKeyIdentifier(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            //      <wsse:KeyIdentifier wsu:Id="..."
            //                          ValueType="..."
            //                          EncodingType="...">
            //          ...
            //      </wsse:KeyIdentifier>

            bool isEmptyElement = reader.IsEmptyElement;
            var keyIdentifier = new KeyIdentifier
            {
                Id = reader.GetAttribute(WsSecurityAttributes.Id),
                EncodingType = reader.GetAttribute(WsSecurityAttributes.EncodingType),
                ValueType = reader.GetAttribute(WsSecurityAttributes.ValueType)
            };

            reader.ReadStartElement();
            if (!isEmptyElement)
            {
                keyIdentifier.Value = reader.ReadContentAsString();
                reader.ReadEndElement();
            }

            return keyIdentifier;
        }

        public void WriteKeyIdentifier(XmlDictionaryWriter writer, WsSerializationContext serializationContext, KeyIdentifier keyIdentifier)
        {
            //  <wsse:KeyIdentifier wsu:Id="..."
            //                      ValueType="..."
            //                      EncodingType="...">
            //      ...
            //  </wsse:KeyIdentifier>

            writer.WriteStartElement(serializationContext.SecurityConstants.Prefix, WsSecurityElements.KeyIdentifier, serializationContext.SecurityConstants.Namespace);

            if (!string.IsNullOrEmpty(keyIdentifier.Id))
                writer.WriteAttributeString(WsSecurityAttributes.Id, keyIdentifier.Id);

            if (!string.IsNullOrEmpty(keyIdentifier.ValueType))
                writer.WriteAttributeString(WsSecurityAttributes.ValueType, keyIdentifier.ValueType);

            if (!string.IsNullOrEmpty(keyIdentifier.EncodingType))
                writer.WriteAttributeString(WsSecurityAttributes.EncodingType, keyIdentifier.EncodingType);

            if (!string.IsNullOrEmpty(keyIdentifier.Value))
                writer.WriteString(keyIdentifier.Value);

            writer.WriteEndElement();
        }

        public void WriteSecurityTokenReference(XmlDictionaryWriter writer, WsSerializationContext serializationContext, SecurityTokenReference securityTokenReference)
        {
            // <wsse:SecurityTokenReference>
            //      <wsse:KeyIdentifier wsu:Id="..."
            //                          ValueType="..."
            //                          EncodingType="...">
            //          ...
            //      </wsse:KeyIdentifier>
            //  </wsse:SecurityTokenReference>

            writer.WriteStartElement(serializationContext.SecurityConstants.Prefix, WsSecurityElements.SecurityTokenReference, serializationContext.SecurityConstants.Namespace);

            if (!string.IsNullOrEmpty(securityTokenReference.TokenType))
                writer.WriteAttributeString(WsSecurityAttributes.TokenType, securityTokenReference.TokenType);

            if (!string.IsNullOrEmpty(securityTokenReference.Id))
                writer.WriteAttributeString(WsSecurityAttributes.Id, securityTokenReference.Id);

            if (securityTokenReference.KeyIdentifier != null)
                WriteKeyIdentifier(writer, serializationContext, securityTokenReference.KeyIdentifier);

            writer.WriteEndElement();
        }
    }
}