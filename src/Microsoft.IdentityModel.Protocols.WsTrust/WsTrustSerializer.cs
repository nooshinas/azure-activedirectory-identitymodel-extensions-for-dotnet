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
using Microsoft.IdentityModel.Protocols.WsAddressing;
using Microsoft.IdentityModel.Protocols.WsFed;
using Microsoft.IdentityModel.Protocols.WsPolicy;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Protocols.WsUtility;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;

#pragma warning disable 1591

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Base class for support of versions of WS-Trust request messages.
    /// </summary>
    public class WsTrustSerializer
    {
        private WsSecuritySerializer _wsSecuritySerializer = new WsSecuritySerializer();
        internal const string GeneratedDateTimeFormat = "yyyy-MM-ddTHH:mm:ss.fffffZ";

        public WsTrustSerializer()
        {
            SecurityTokenHandlers = new Collection<SecurityTokenHandler>
            {
                new SamlSecurityTokenHandler(),
                new Saml2SecurityTokenHandler()
            };
        }

        public WsTrustResponse ReadResponse(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, WsTrustElements.RequestSecurityTokenResponseCollection);
            WsSerializationContext serializationContext;
            if (reader.IsNamespaceUri(WsTrustConstants.Trust13.Namespace))
                serializationContext = new WsSerializationContext(WsTrustVersion.Trust13);
            else if (reader.IsNamespaceUri(WsTrustConstants.TrustFeb2005.Namespace))
                serializationContext = new WsSerializationContext(WsTrustVersion.TrustFeb2005);
            else if (reader.IsNamespaceUri(WsTrustConstants.Trust14.Namespace))
                serializationContext = new WsSerializationContext(WsTrustVersion.Trust14);
            else
                throw LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(LogMessages.IDX15001, WsTrustConstants.TrustFeb2005, WsTrustConstants.Trust13, WsTrustConstants.Trust14, reader.NamespaceURI)));

            reader.ReadStartElement();
            return ReadResponse(reader, serializationContext);
        }

        public WsTrustResponse ReadResponse(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (serializationContext == null)
                throw LogHelper.LogArgumentNullException(nameof(serializationContext));

            bool isEmptyElement = reader.IsEmptyElement;
            bool hasRstrCollection = false;
            var response = new WsTrustResponse();
            if (reader.IsStartElement(WsTrustElements.RequestSecurityTokenResponseCollection, serializationContext.TrustConstants.Namespace))
            {
                reader.ReadStartElement();
                hasRstrCollection = true;
            }

            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(WsTrustElements.RequestSecurityTokenResponse, serializationContext.TrustConstants.Namespace))
                    response.RequestSecurityTokenResponseCollection.Add(ReadResponseInternal(reader, serializationContext));
                else
                    // brentsch - need to put these elements in array
                    reader.Skip();
            }

            if (!isEmptyElement && hasRstrCollection)
                    reader.ReadEndElement();

            return response;
        }

        public RequestSecurityTokenResponse ReadRequestSeurityTokenResponse(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            XmlUtil.CheckReaderOnEntry(reader, WsTrustElements.RequestSecurityTokenResponse, serializationContext.TrustConstants.Namespace);
            return ReadResponseInternal(reader, serializationContext);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="serializationContext"></param>
        /// <returns></returns>
        public RequestSecurityTokenResponse ReadResponseInternal(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            bool isEmptyElement = reader.IsEmptyElement;
            var tokenResponse = new RequestSecurityTokenResponse();
            bool processed = false;
            reader.ReadStartElement();
            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(WsTrustElements.TokenType, serializationContext.TrustConstants.Namespace))
                {
                    tokenResponse.TokenType = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.Lifetime, serializationContext.TrustConstants.Namespace))
                {
                    tokenResponse.Lifetime = ReadLifetime(reader, serializationContext);
                }
                else if (reader.IsStartElement(WsTrustElements.KeyType, serializationContext.TrustConstants.Namespace))
                {
                    tokenResponse.KeyType = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.RequestedSecurityToken, serializationContext.TrustConstants.Namespace))
                {
                    tokenResponse.RequestedSecurityToken = ReadRequestedSecurityToken(reader, serializationContext);
                }
                else if (reader.IsStartElement(WsTrustElements.RequestedAttachedReference, serializationContext.TrustConstants.Namespace))
                {
                    tokenResponse.AttachedReference = ReadReference(reader, serializationContext);
                }
                else if (reader.IsStartElement(WsTrustElements.RequestedUnattachedReference, serializationContext.TrustConstants.Namespace))
                {
                    tokenResponse.UnattachedReference = ReadReference(reader, serializationContext);
                }
                else if (reader.IsStartElement(WsTrustElements.RequestedProofToken, serializationContext.TrustConstants.Namespace))
                {
                    tokenResponse.RequestedProofToken = ReadRequestedProofToken(reader, serializationContext);
                }
                else if (reader.IsStartElement(WsTrustElements.Entropy, serializationContext.TrustConstants.Namespace))
                {
                    tokenResponse.Entropy = ReadEntropy(reader, serializationContext);
                }
                else if (reader.IsLocalName(WsPolicyElements.AppliesTo))
                {
                    foreach (var @namespace in WsPolicyConstants.KnownNamespaces)
                    {
                        if (reader.IsNamespaceUri(@namespace))
                        {
                            tokenResponse.AppliesTo = ReadAppliesTo(reader, @namespace);
                            processed = true;
                            break;
                        }
                    }

                    if (!processed)
                        reader.Skip();
                }
                else
                {
                    reader.Skip();
                }
            }

            if (!isEmptyElement)
                reader.ReadEndElement();

            return tokenResponse;
        }

        public RequestedSecurityToken ReadRequestedSecurityToken(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            XmlUtil.CheckReaderOnEntry(reader, WsTrustElements.RequestedSecurityToken);
            bool isEmptyElement = reader.IsEmptyElement;
            bool wasTokenRead = false;
            reader.ReadStartElement();
            reader.MoveToContent();
            RequestedSecurityToken requestedSecurityToken = new RequestedSecurityToken();
            foreach (var tokenHandler in SecurityTokenHandlers)
            {
                // brentsch - TODO need to remember value if handler can't be found.
                // perhaps add delegate?
                if (tokenHandler.CanReadToken(reader))
                {
                    requestedSecurityToken = new RequestedSecurityToken(tokenHandler.ReadToken(reader));
                    wasTokenRead = true;
                    break;
                }
            }

            // brentsch - TODO TEST
            if (!wasTokenRead && !isEmptyElement)
                reader.Skip();

            if (!isEmptyElement)
                reader.ReadEndElement();

            return requestedSecurityToken;
        }

        public UseKey ReadUseKey(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            //<t:UseKey Sig="...">
            // SecurityTokenReference - optional
            //</t:UseKey>

            bool isEmptyElement = reader.IsEmptyElement;
            string signatureId = reader.GetAttribute(WsTrustAttributes.Sig, serializationContext.TrustConstants.Namespace);

            reader.ReadStartElement();
            UseKey useKey = new UseKey();

            if (reader.IsStartElement() && reader.IsLocalName(WsSecurityElements.SecurityTokenReference))
                useKey.SecurityTokenReference = _wsSecuritySerializer.ReadSecurityTokenReference(reader, serializationContext);

            if (!string.IsNullOrEmpty(signatureId))
                useKey.SignatureId = signatureId;

            if (!isEmptyElement)
                reader.ReadEndElement();

            return useKey;
        }

        public SecurityTokenReference ReadReference(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            //  <RequestedAttachedReference>
            //      <wsse:SecurityTokenReference ...>
            //          ...
            //      </wsse:SecurityTokenReference ...>
            //  </RequestedAttachedReference>

            //  <RequestedUnattachedReference>
            //      <wsse:SecurityTokenReference ...>
            //          ...
            //      </wsse:SecurityTokenReference ...>
            //  </RequestedUnattachedReference>

            bool isEmptyElement = reader.IsEmptyElement;
            reader.ReadStartElement();
            var retVal = _wsSecuritySerializer.ReadSecurityTokenReference(reader, serializationContext);

            if (!isEmptyElement)
                reader.ReadEndElement();

            return retVal;
        }

        public RequestedProofToken ReadRequestedProofToken(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            //<wst:RequestedProofToken>
            //    <wst:BinarySecret>5p76ToaxZXMFm4W6fmCcFXfDPd9WgJIM</wst:BinarySecret>
            //</wst:RequestedProofToken>

            XmlUtil.CheckReaderOnEntry(reader, WsTrustElements.RequestedProofToken, serializationContext.TrustConstants.Namespace);
            var isEmptyElement = reader.IsEmptyElement;
            reader.ReadStartElement();
            BinarySecret binarySecret = null;
            if (reader.IsStartElement(WsTrustElements.BinarySecret, serializationContext.TrustConstants.Namespace))
            {
                if (reader.IsEmptyElement)
                    // brentsch - TODO, error message
                    throw LogHelper.LogExceptionMessage(new WsTrustReadException("BinarySecret is empty element"));

                var type = reader.GetAttribute(WsTrustAttributes.Type, serializationContext.TrustConstants.Namespace);
                var data = reader.ReadContentAsBase64();

                if (!string.IsNullOrEmpty(type) && data != null)
                    binarySecret = new BinarySecret(data, type);
                else if (data != null)
                    binarySecret = new BinarySecret(data);
                else
                    // brentsch - TODO, error message
                    throw LogHelper.LogExceptionMessage(new WsTrustReadException("BinarySecret missing"));
            }
            else
            {
                // brentsch - TODO, test for empty element
                reader.Skip();
            }

            // brentsch - TODO, add additional scenarios for Requested proof token;
            RequestedProofToken proofToken = null;
            if (binarySecret != null)
                proofToken = new RequestedProofToken(binarySecret);
            else
                LogHelper.LogExceptionMessage(new WsTrustReadException("The only Supported scenario is: BinarySecret in Requested Proof token"));

            if (!isEmptyElement)
                reader.ReadEndElement();

            return proofToken;
        }

        public Entropy ReadEntropy(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            //  <wst:Entropy>
            //      <wst:BinarySecret>
            //          ...
            //      </wst:BinarySecret>
            //  </wst:Entropy>

            XmlUtil.CheckReaderOnEntry(reader, WsTrustElements.Entropy, serializationContext.TrustConstants.Namespace);
            bool isEmptyElement = reader.IsEmptyElement;
            reader.ReadStartElement();
            var entropy = new Entropy();
            if (reader.IsStartElement(WsTrustElements.BinarySecret, serializationContext.TrustConstants.Namespace))
            {
                var type = reader.GetAttribute(WsTrustAttributes.Type, serializationContext.TrustConstants.Namespace);
                var secrect = reader.ReadElementContentAsBase64();
                entropy.BinarySecret = new BinarySecret(secrect, type);
            }

            if (!isEmptyElement)
                reader.ReadEndElement();

            return entropy;
        }

        public Lifetime ReadLifetime(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            //  <t:Lifetime>
            //      <wsu:Created xmlns:wsu="...">2017-04-23T16:11:17.348Z</wsu:Created>
            //      <wsu:Expires xmlns:wsu="...">2017-04-23T17:11:17.348Z</wsu:Expires>
            //  </t:Lifetime>

            XmlUtil.CheckReaderOnEntry(reader, WsTrustElements.Lifetime, serializationContext.TrustConstants.Namespace);
            bool isEmptyElement = reader.IsEmptyElement;
            reader.ReadStartElement();
            var lifetime = new Lifetime(null, null);

            if (reader.IsStartElement() && reader.IsLocalName(WsUtilityElements.Created))
                lifetime.Created = XmlConvert.ToDateTime(XmlUtil.ReadStringElement(reader), XmlDateTimeSerializationMode.Utc);

            if (reader.IsStartElement() && reader.IsLocalName(WsUtilityElements.Expires))
                lifetime.Expires = XmlConvert.ToDateTime(XmlUtil.ReadStringElement(reader), XmlDateTimeSerializationMode.Utc);

            if (!isEmptyElement)
                reader.ReadEndElement();

            return lifetime;
        }

        public WsTrustRequest ReadRequest(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, WsTrustElements.RequestSecurityToken);
            reader.MoveToContent();
            WsSerializationContext serializationContext;
            if (reader.IsNamespaceUri(WsTrustConstants.Trust13.Namespace))
                serializationContext = new WsSerializationContext(WsTrustVersion.Trust13);
            else if (reader.IsNamespaceUri(WsTrustConstants.TrustFeb2005.Namespace))
                serializationContext = new WsSerializationContext(WsTrustVersion.TrustFeb2005);
            else if (reader.IsNamespaceUri(WsTrustConstants.Trust14.Namespace))
                serializationContext = new WsSerializationContext(WsTrustVersion.Trust14);
            else
                throw LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(LogMessages.IDX15001, WsTrustConstants.TrustFeb2005, WsTrustConstants.Trust13, WsTrustConstants.Trust14, reader.NamespaceURI)));

            var trustRequest = new WsTrustRequest
            {
                Context = reader.GetAttribute(WsTrustAttributes.Context)
            };

            reader.MoveToContent();
            reader.ReadStartElement();
            ReadRequest(reader, serializationContext, trustRequest);

            // brentsch TODO - need to store unknown elements.
            return trustRequest;
        }

        public WsTrustRequest ReadRequest(XmlDictionaryReader reader, WsSerializationContext serializationContext, WsTrustRequest trustRequest)
        {
            // brentsch - TODO, PERF - create a collection of strings assuming only single elements
 
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (serializationContext == null)
                throw LogHelper.LogArgumentNullException(nameof(serializationContext));

            bool isEmptyElement = reader.IsEmptyElement;
            while (reader.IsStartElement())
            {
                bool processed = false;
                if (reader.IsStartElement(WsTrustElements.RequestType, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.RequestType = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.OnBehalfOf, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.OnBehalfOf = ReadOnBehalfOf(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.TokenType, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.TokenType = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.KeyType, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.KeyType = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.KeySize, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.KeySizeInBits = XmlUtil.ReadIntElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.CanonicalizationAlgorithm, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.CanonicalizationAlgorithm = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.EncryptionAlgorithm, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.EncryptionAlgorithm = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.EncryptWith, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.EncryptWith = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.SignWith, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.SignWith = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.ComputedKeyAlgorithm, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.ComputedKeyAlgorithm = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.UseKey, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.UseKey = ReadUseKey(reader, serializationContext);
                }
                else if (reader.IsLocalName(WsPolicyElements.AppliesTo))
                {
                    foreach (var @namespace in WsPolicyConstants.KnownNamespaces)
                    {
                        if (reader.IsNamespaceUri(@namespace))
                        {
                            trustRequest.AppliesTo = ReadAppliesTo(reader, @namespace);
                            processed = true;
                            break;
                        }
                    }

                    if (!processed)
                        reader.Skip();
                }
                else if (reader.IsLocalName(WsFedElements.AdditionalContext))
                {
                    foreach (var @namespace in WsFedConstants.KnownAuthNamespaces)
                    {
                        if (reader.IsNamespaceUri(@namespace))
                        {
                            trustRequest.AdditionalContext = ReadAdditionalContext(reader, @namespace);
                            processed = true;
                            break;
                        }
                    }

                    if (!processed)
                        reader.Skip();
                }
                else if (reader.IsStartElement(WsTrustElements.Claims, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.Claims = ReadClaims(reader, serializationContext);
                }
                else if (reader.IsLocalName(WsPolicyElements.PolicyReference))
                {
                    foreach (var @namespace in WsPolicyConstants.KnownNamespaces)
                    {
                        if (reader.IsNamespaceUri(@namespace))
                        {
                            trustRequest.PolicyReference = ReadPolicyReference(reader, @namespace);
                            processed = true;
                            break;
                        }
                    }
                }
                else
                {
                    reader.Skip();
                }
            }

            if (!isEmptyElement)
                reader.ReadEndElement();

            return trustRequest;
        }

        /// <summary>
        /// 
        /// </summary>
        public virtual AdditionalContext ReadAdditionalContext(XmlDictionaryReader reader, string @namespace)
        {
            //  <auth:AdditionalContext xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706">
            //    <auth:ContextItem Name="http://referenceUri" Scope="8954b59e-3907-4939-976d-959395583ecb">
            //      <auth:Value>90b88c42-55ca-4e4c-a45f-cde102383f3b</auth:Value>
            //    </auth:ContextItem>
            //  </auth:AdditionalContext>

            XmlUtil.CheckReaderOnEntry(reader, WsFedElements.AdditionalContext);
            var additionalContext = new AdditionalContext();
            if (reader.IsEmptyElement)
                return additionalContext;

            // brentsch - TODO, this is an open spec, we are skipping all unknown attributes.
            reader.ReadStartElement();
            reader.MoveToContent();
            try
            {
                while (reader.IsStartElement())
                {
                    // brentsch - TODO, need to account for namespace
                    if (!reader.IsEmptyElement && reader.IsStartElement(WsFedElements.ContextItem, @namespace))
                    {
                        var name = reader.GetAttribute(WsFedAttributes.Name);
                        if (string.IsNullOrEmpty(name))
                            throw LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(Xml.LogMessages.IDX30013, WsFedElements.ContextItem, WsFedAttributes.Name)));

                        var contextItem = new ContextItem(name);
                        contextItem.Scope = reader.GetAttribute(WsFedAttributes.Scope);
                        reader.ReadStartElement();
                        reader.MoveToContent();
                        if (!reader.IsEmptyElement && reader.IsStartElement(WsFedElements.Value, @namespace))
                        {
                            reader.ReadStartElement();
                            contextItem.Value = reader.ReadContentAsString();
                            reader.MoveToContent();
                            reader.ReadEndElement();
                        }
                        else
                        {
                            reader.Skip();
                        }

                        // </ContextItem>
                        reader.ReadEndElement();
                        additionalContext.Items.Add(contextItem);
                    }
                    else
                    {
                        reader.Skip();
                    }

                    reader.MoveToContent();
                }
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(Xml.LogMessages.IDX30016, WsFedElements.ContextItem), ex));
            }

            // </AdditionalContext>
            reader.ReadEndElement();
            return additionalContext;
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="reader">The xml dictionary reader.</param>
        /// <param name="namespace"></param>
        /// <returns>An <see cref="EndpointReference"/> instance.</returns>
        public virtual AppliesTo ReadAppliesTo(XmlDictionaryReader reader, string @namespace)
        {
            XmlUtil.CheckReaderOnEntry(reader, WsPolicyElements.AppliesTo, @namespace);

            // brentsch - TODO, TESTCASE
            if (reader.IsEmptyElement)
            {
                reader.Skip();
                return new AppliesTo();
            }

            reader.ReadStartElement();
            var appliesTo = new AppliesTo { EndpointReference = ReadEndpointReference(reader) };
            reader.ReadEndElement();

            return appliesTo;
        }

        public virtual Claims ReadClaims(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            // brensch - TODO WsFedSerializer?
            // <trust:Claims 
            //  Dialect="edef1723d88b4897a8792d2fc62f9148">
            //      <auth:ClaimType 
            //            Uri="a14bf1a3a1894a819d9a7d3dfeb7724a">
            //          <auth:Value>
            //              77a6fa0404544d0887612a840e281399
            //          </auth:Value>
            //      </auth:ClaimType>
            // </trust:Claims>

            XmlUtil.CheckReaderOnEntry(reader, WsTrustElements.Claims, serializationContext.TrustConstants.Namespace);
            bool isEmptyElement = reader.IsEmptyElement;
            var dialect = reader.GetAttribute(WsTrustAttributes.Dialect);
            reader.ReadStartElement();
            var claimTypes = new List<ClaimType>();
            while (reader.IsStartElement())
            {
                if (reader.IsLocalName(WsFedElements.ClaimType))
                {
                    foreach (var @namespace in WsFed12Constants.KnownAuthNamespaces)
                    {
                        if (reader.IsNamespaceUri(@namespace))
                        {
                            claimTypes.Add(ReadClaimType(reader, @namespace));
                        }
                    }
                }
                else
                {
                    reader.Skip();
                }
            }

            if (!isEmptyElement)
                reader.ReadEndElement();

            return new Claims(dialect, claimTypes);
        }

        /// <summary>
        /// Creates and populates a <see cref="ClaimType"/> by reading xml.
        /// Expects the <see cref="XmlDictionaryReader"/> to be positioned on the StartElement: "ClaimType" in the namespace passed in.
        /// </summary>
        /// <param name="reader">a <see cref="XmlDictionaryReader"/> positioned at the StartElement: "ClaimType".</param>
        /// <param name="namespace">the namespace for the StartElement.</param>
        /// <returns>a populated <see cref="ClaimType"/>.</returns>
        /// <remarks>Checking for the correct StartElement is as follows.</remarks>
        /// <remarks>if @namespace is null, then <see cref="XmlDictionaryReader.IsLocalName(string)"/> will be called.</remarks>
        /// <remarks>if @namespace is not null or empty, then <see cref="XmlDictionaryReader.IsStartElement(XmlDictionaryString, XmlDictionaryString)"/> will be called.></remarks>
        /// <exception cref="ArgumentNullException">if reader is null.</exception>
        /// <exception cref="XmlReadException">if reader is not positioned on a StartElement.</exception>
        /// <exception cref="XmlReadException">if the StartElement does not match the expectations in remarks.</exception>
        public virtual ClaimType ReadClaimType(XmlDictionaryReader reader, string @namespace)
        {
            // <auth:ClaimType 
            //      Uri="a14bf1a3-a189-4a81-9d9a-7d3dfeb7724a"
            //      Optional="true/false">
            //   <auth:Value>
            //      77a6fa04-0454-4d08-8761-2a840e281399
            //   </auth:Value>
            // </auth:ClaimType>

            XmlUtil.CheckReaderOnEntry(reader, WsFedElements.ClaimType, @namespace);
            var uri = reader.GetAttribute(WsFedAttributes.Uri);
            if (string.IsNullOrEmpty(uri))
                throw LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(Xml.LogMessages.IDX30013, WsFedElements.ContextItem, WsFedAttributes.Name)));

            var optionalAttribute = reader.GetAttribute(WsFedAttributes.Optional);
            bool? optional = null;
            if (!string.IsNullOrEmpty(optionalAttribute))
                optional = XmlConvert.ToBoolean(optionalAttribute);

            string value = null;
            bool isEmptyElement = reader.IsEmptyElement;
            reader.ReadStartElement();
            reader.MoveToContent();

            // brentsch - TODO, need loop for multiple elements
            if (reader.IsStartElement(WsFedElements.Value, @namespace))
                value = XmlUtil.ReadStringElement(reader);

            if (!isEmptyElement)
                reader.ReadEndElement();

            // brentsch - TODO, TESTCASE
            if (optional.HasValue && !string.IsNullOrEmpty(value))
                return new ClaimType { Uri = uri, IsOptional = optional, Value = value };
            else if (optional.HasValue)
                return new ClaimType { Uri = uri, IsOptional = optional };
            else if (!string.IsNullOrEmpty(value))
                return new ClaimType { Uri = uri, Value = value };

            return new ClaimType { Uri = uri };
        }

        /// <summary>
        /// Reads an <see cref="EndpointReference"/>
        /// </summary>
        /// <param name="reader">The xml dictionary reader.</param>
        /// <returns>An <see cref="EndpointReference"/> instance.</returns>
        public virtual EndpointReference ReadEndpointReference(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, WsAddressingElements.EndpointReference);
            
            reader.MoveToContent();
            foreach(var @namespace in WsAddressingConstants.KnownNamespaces)
            {
                if (reader.IsNamespaceUri(@namespace))
                {
                    bool isEmptyElement = reader.IsEmptyElement;
                    reader.ReadStartElement();
                    var endpointReference = new EndpointReference(reader.ReadElementContentAsString());
                    while (reader.IsStartElement())
                    {
                        bool isInnerEmptyElement = reader.IsEmptyElement;
                        var subtreeReader = reader.ReadSubtree();
                        var doc = new XmlDocument
                        {
                            PreserveWhitespace = true
                        };

                        doc.Load(subtreeReader);
                        endpointReference.AdditionalXmlElements.Add(doc.DocumentElement);
                        if (!isInnerEmptyElement)
                            reader.ReadEndElement();
                    }

                    if (!isEmptyElement)
                        reader.ReadEndElement();

                    return endpointReference;
                }
            }

            throw LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(LogMessages.IDX15002, WsAddressingElements.EndpointReference, WsAddressingConstants.Addressing200408.Namespace, WsAddressingConstants.Addressing10.Namespace, reader.NamespaceURI)));
        }

        public virtual SecurityToken ReadOnBehalfOf(XmlDictionaryReader reader)
        {
            reader.MoveToContent();
            bool isEmptyElement = reader.IsEmptyElement;
            reader.ReadStartElement();
            foreach (var tokenHandler in SecurityTokenHandlers)
            {
                if (tokenHandler.CanReadToken(reader))
                {
                    var token = tokenHandler.ReadToken(reader);
                    if (!isEmptyElement)
                        reader.ReadEndElement();

                    return token;
                }
            }

            // brentsch - TODO localize error message
            throw LogHelper.LogExceptionMessage(new WsTrustReadException("unable to read token"));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="namespace"></param>
        public virtual PolicyReference ReadPolicyReference(XmlDictionaryReader reader, string @namespace)
        {
            // brentsch - TODO, if this was private, we wouldn't need to check as much
            XmlUtil.CheckReaderOnEntry(reader, WsPolicyElements.PolicyReference, @namespace);

            bool isEmptyElement = reader.IsEmptyElement;
            var uri = reader.GetAttribute(WsPolicyAttributes.URI);
            var digest = reader.GetAttribute(WsPolicyAttributes.Digest);
            var digestAlgorithm = reader.GetAttribute(WsPolicyAttributes.DigestAlgorithm);
            reader.ReadStartElement();
            reader.MoveToContent();

            if (!isEmptyElement)
                reader.ReadEndElement();

            return new PolicyReference(uri, digest, digestAlgorithm);
        }

        public ICollection<SecurityTokenHandler> SecurityTokenHandlers { get; private set; }

        public void WriteRequest(XmlDictionaryWriter writer, WsTrustVersion wsTrustVersion, WsTrustRequest trustRequest)
        {
            WriteRequest(writer, new WsSerializationContext(wsTrustVersion), trustRequest);
        }

        public void WriteRequest(XmlDictionaryWriter writer, WsSerializationContext serializationContext, WsTrustRequest trustRequest)
        {
            ValidateParamsForWritting(writer, serializationContext, trustRequest, nameof(trustRequest));
            writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.RequestSecurityToken, serializationContext.TrustConstants.Namespace);
            if (!string.IsNullOrEmpty(trustRequest.Context))
                writer.WriteAttributeString(WsTrustAttributes.Context, trustRequest.Context);

            writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.RequestType, serializationContext.TrustConstants.Namespace, trustRequest.RequestType);

            if (!string.IsNullOrEmpty(trustRequest.TokenType))
                writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.TokenType, serializationContext.TrustConstants.Namespace, trustRequest.TokenType);

            if (!string.IsNullOrEmpty(trustRequest.KeyType))
                writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.KeyType, serializationContext.TrustConstants.Namespace, trustRequest.KeyType);

            if (trustRequest.KeySizeInBits.HasValue)
            {
                writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.KeySize, serializationContext.TrustConstants.Namespace);
                writer.WriteValue(trustRequest.KeySizeInBits.Value);
                writer.WriteEndElement();
            }

            if (!string.IsNullOrEmpty(trustRequest.CanonicalizationAlgorithm))
                writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.CanonicalizationAlgorithm, serializationContext.TrustConstants.Namespace, trustRequest.CanonicalizationAlgorithm);

            if (!string.IsNullOrEmpty(trustRequest.EncryptionAlgorithm))
                writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.EncryptionAlgorithm, serializationContext.TrustConstants.Namespace, trustRequest.EncryptionAlgorithm);

            if (!string.IsNullOrEmpty(trustRequest.EncryptWith))
                writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.EncryptWith, serializationContext.TrustConstants.Namespace, trustRequest.EncryptWith);

            if (!string.IsNullOrEmpty(trustRequest.SignWith))
                writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.SignWith, serializationContext.TrustConstants.Namespace, trustRequest.SignWith);

            if (!string.IsNullOrEmpty(trustRequest.ComputedKeyAlgorithm))
                writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.ComputedKeyAlgorithm, serializationContext.TrustConstants.Namespace, trustRequest.ComputedKeyAlgorithm);

            if (trustRequest.AppliesTo != null)
                WriteAppliesTo(writer, serializationContext, trustRequest.AppliesTo);

            if (trustRequest.OnBehalfOf != null)
                WriteOnBehalfOf(writer, serializationContext, trustRequest.OnBehalfOf);

            if (trustRequest.AdditionalContext != null)
                WriteAdditionalContext(writer, serializationContext, trustRequest.AdditionalContext);

            if (trustRequest.Claims != null)
                WriteClaims(writer, serializationContext, trustRequest.Claims);

            if (trustRequest.PolicyReference != null)
                WritePolicyReference(writer, serializationContext, trustRequest.PolicyReference);

            if (trustRequest.UseKey != null)
                WriteUseKey(writer, serializationContext, trustRequest.UseKey);

            writer.WriteEndElement();
        }

        public void WriteResponse(XmlDictionaryWriter writer, WsTrustVersion wsTrustVersion, WsTrustResponse trustResponse)
        {
            WriteResponse(writer, new WsSerializationContext(wsTrustVersion), trustResponse);
        }

        public void WriteResponse(XmlDictionaryWriter writer, WsSerializationContext serializationContext, WsTrustResponse trustResponse)
        {
            //brentsch - TODO account for trust version, only 1.3+ have collection
            ValidateParamsForWritting(writer, serializationContext, trustResponse, nameof(trustResponse));
            writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.RequestSecurityTokenResponseCollection, serializationContext.TrustConstants.Namespace);
            foreach (var response in trustResponse.RequestSecurityTokenResponseCollection)
            {
                writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.RequestSecurityTokenResponse, serializationContext.TrustConstants.Namespace);

                if (!string.IsNullOrEmpty(response.Context))
                    writer.WriteAttributeString(WsTrustAttributes.Context, response.Context);

                if (response.AttachedReference != null)
                    WriteAttachedReference(writer, serializationContext, response.AttachedReference);

                if (response.UnattachedReference != null)
                    WriteUnattachedReference(writer, serializationContext, response.UnattachedReference);

                if (response.Lifetime != null)
                    WriteLifetime(writer, serializationContext, response.Lifetime);

                if (!string.IsNullOrEmpty(response.TokenType))
                    writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.TokenType, serializationContext.TrustConstants.Namespace, response.TokenType);

                if (response.RequestedSecurityToken != null)
                    WriteRequestedSecurityToken(writer, serializationContext, response.RequestedSecurityToken);

                if (!string.IsNullOrEmpty(response.KeyType))
                    writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.KeyType, serializationContext.TrustConstants.Namespace, response.KeyType);

                // AppliesTo
                if (response.AppliesTo != null)
                    WriteAppliesTo(writer, serializationContext, response.AppliesTo);

                // Entropy:
                if (response.Entropy != null)
                    WriteEntropy(writer, serializationContext, response.Entropy);

                // KeyType:
                if (!string.IsNullOrEmpty(response.KeyType))
                    writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.KeyType, serializationContext.TrustConstants.Namespace, response.KeyType);

                // </RequestSecurityTokenResponse>;
                writer.WriteEndElement();
            }

            // </RequestSecurityTokenResponseCollection>
            writer.WriteEndElement();

        }

        public void WriteLifetime(XmlDictionaryWriter writer, WsSerializationContext serializationContext, Lifetime lifetime)
        {
            //  <t:Lifetime>
            //      <wsu:Created xmlns:wsu="...">2017-04-23T16:11:17.348Z</wsu:Created>
            //      <wsu:Expires xmlns:wsu="...">2017-04-23T17:11:17.348Z</wsu:Expires>
            //  </t:Lifetime>

            ValidateParamsForWritting(writer, serializationContext, lifetime, nameof(lifetime));
            writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.Lifetime, serializationContext.TrustConstants.Namespace);
            if (lifetime.Created.HasValue)
            {
                writer.WriteStartElement(WsUtilityConstants.WsUtility10.Prefix, WsUtilityElements.Created, WsUtilityConstants.WsUtility10.Namespace);
                writer.WriteString(XmlConvert.ToString(lifetime.Created.Value.ToUniversalTime(), GeneratedDateTimeFormat));
                writer.WriteEndElement();
            }

            if (lifetime.Expires.HasValue)
            {
                writer.WriteStartElement(WsUtilityConstants.WsUtility10.Prefix, WsUtilityElements.Expires, WsUtilityConstants.WsUtility10.Namespace);
                writer.WriteString(XmlConvert.ToString(lifetime.Expires.Value.ToUniversalTime(), GeneratedDateTimeFormat));
                writer.WriteEndElement();
            }

            writer.WriteEndElement();
        }

        public void WriteOnBehalfOf(XmlDictionaryWriter writer, WsSerializationContext serializationContext, SecurityToken securityToken)
        {
            ValidateParamsForWritting(writer, serializationContext, securityToken, nameof(securityToken));
            writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.OnBehalfOf, serializationContext.TrustConstants.Namespace);
            foreach (var tokenHandler in SecurityTokenHandlers)
            {
                if (tokenHandler.CanWriteSecurityToken(securityToken))
                {
                    if (!tokenHandler.TryWriteSourceData(writer, securityToken))
                        tokenHandler.WriteToken(writer, securityToken);
                }
            }

            writer.WriteEndElement();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="serializationContext"></param>
        /// <param name="additionalContext"></param>
        public void WriteAdditionalContext(XmlDictionaryWriter writer, WsSerializationContext serializationContext, AdditionalContext additionalContext)
        {
            // brentsch - TODO consider WsFedSerializer

            //  <auth:AdditionalContext>
            //    <auth:ContextItem Name="xs:anyURI" Scope="xs:anyURI" ? ...>
            //      (<auth:Value>xs:string</auth:Value> |
            //       xs:any ) ?
            //    </auth:ContextItem> *
            //    ...
            //  </auth:AdditionalContext>

            ValidateParamsForWritting(writer, serializationContext, additionalContext, nameof(additionalContext));
            writer.WriteStartElement(serializationContext.FedConstants.AuthPrefix, WsFedElements.AdditionalContext, serializationContext.FedConstants.AuthNamespace);
            foreach (var contextItem in additionalContext.Items)
            {
                writer.WriteStartElement(serializationContext.FedConstants.AuthPrefix, WsFedElements.ContextItem, serializationContext.FedConstants.AuthNamespace);
                writer.WriteAttributeString(WsFedAttributes.Name, contextItem.Name);
                if (contextItem.Scope != null)
                    writer.WriteAttributeString(WsFedAttributes.Scope, contextItem.Scope);

                if (!string.IsNullOrEmpty(contextItem.Value))
                    writer.WriteElementString(serializationContext.FedConstants.AuthPrefix, WsFedElements.Value, serializationContext.FedConstants.AuthNamespace, contextItem.Value);

                writer.WriteEndElement();
            }

            writer.WriteEndElement();
        }

        public void WriteAppliesTo(XmlDictionaryWriter writer, WsSerializationContext serializationContext, AppliesTo appliesTo)
        {
            ValidateParamsForWritting(writer, serializationContext, appliesTo, nameof(appliesTo));
            writer.WriteStartElement(serializationContext.PolicyConstants.Prefix, WsPolicyElements.AppliesTo, serializationContext.PolicyConstants.Namespace);
            if (appliesTo.EndpointReference != null)
                WriteEndpointReference(writer, serializationContext, appliesTo.EndpointReference);

            writer.WriteEndElement();
        }

        public void WriteAttachedReference(XmlDictionaryWriter writer, WsSerializationContext serializationContext, SecurityTokenReference securityTokenReference)
        {
            //<t:RequestedAttachedReference>
            //    <SecurityTokenReference d3p1:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0" xmlns:d3p1=""http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"" xmlns=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"">
            //        <KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID">_edc15efd-1117-4bf9-89da-28b1663fb890</KeyIdentifier>
            //    </SecurityTokenReference>
            //</t:RequestedAttachedReference>

            ValidateParamsForWritting(writer, serializationContext, securityTokenReference, nameof(securityTokenReference));
            writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.RequestedAttachedReference, serializationContext.TrustConstants.Namespace);
            _wsSecuritySerializer.WriteSecurityTokenReference(writer, serializationContext, securityTokenReference);
            writer.WriteEndElement();
        }

        public void WriteUnattachedReference(XmlDictionaryWriter writer, WsSerializationContext serializationContext, SecurityTokenReference securityTokenReference)
        {
            //  <t:RequestedUnattachedReference>
            //    <SecurityTokenReference d3p1:TokenType=""http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"" xmlns:d3p1=""http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"" xmlns=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"">
            //        <KeyIdentifier ValueType=""http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID"">_edc15efd-1117-4bf9-89da-28b1663fb890</KeyIdentifier>
            //    </SecurityTokenReference>
            //  </t:RequestedUnattachedReference>

            ValidateParamsForWritting(writer, serializationContext, securityTokenReference, nameof(securityTokenReference));
            writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.RequestedUnattachedReference, serializationContext.TrustConstants.Namespace);
            _wsSecuritySerializer.WriteSecurityTokenReference(writer, serializationContext, securityTokenReference);
            writer.WriteEndElement();
        }

        public void WriteUseKey(XmlDictionaryWriter writer, WsSerializationContext serializationContext, UseKey useKey)
        {
            //<t:UseKey Sig="...">
            // SecurityToken OR SecurityTokenReference
            //</t:UseKey>

            ValidateParamsForWritting(writer, serializationContext, useKey, nameof(useKey));
            writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.UseKey, serializationContext.TrustConstants.Namespace);
            if (!string.IsNullOrEmpty(useKey.SignatureId))
                writer.WriteAttributeString(WsTrustAttributes.Sig, serializationContext.TrustConstants.Namespace, useKey.SignatureId);
            
            if (useKey.SecurityTokenReference != null)
                _wsSecuritySerializer.WriteSecurityTokenReference(writer, serializationContext, useKey.SecurityTokenReference);

            writer.WriteEndElement();
        }

        public void WriteClaims(XmlDictionaryWriter writer, WsSerializationContext serializationContext, Claims claims)
        {
            ValidateParamsForWritting(writer, serializationContext, claims, nameof(claims));
            writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.Claims, serializationContext.TrustConstants.Namespace);
            if (!string.IsNullOrEmpty(claims.Dialect))
                writer.WriteAttributeString(WsTrustAttributes.Dialect, claims.Dialect);

            foreach (var claim in claims.ClaimTypes)
            {
                writer.WriteStartElement(serializationContext.FedConstants.AuthPrefix, WsFedElements.ClaimType, serializationContext.FedConstants.AuthNamespace);
                writer.WriteAttributeString(WsFedAttributes.Uri, claim.Uri);
                if (claim.IsOptional.HasValue)
                    writer.WriteAttributeString(WsFedAttributes.Optional, XmlConvert.ToString(claim.IsOptional.Value));

                writer.WriteElementString(serializationContext.FedConstants.AuthPrefix, WsFedElements.Value, serializationContext.FedConstants.AuthNamespace, claim.Value);
                writer.WriteEndElement();
            }

            writer.WriteEndElement();
        }

        public void WriteEndpointReference(XmlDictionaryWriter writer, WsSerializationContext serializationContext, EndpointReference endpointReference)
        {
            ValidateParamsForWritting(writer, serializationContext, endpointReference, nameof(endpointReference));
            writer.WriteStartElement(serializationContext.AddressingConstants.Prefix, WsAddressingElements.EndpointReference, serializationContext.AddressingConstants.Namespace);
            writer.WriteStartElement(serializationContext.AddressingConstants.Prefix, WsAddressingElements.Address, serializationContext.AddressingConstants.Namespace);
            writer.WriteString(endpointReference.Uri.AbsoluteUri);
            writer.WriteEndElement();
            foreach (XmlElement element in endpointReference.AdditionalXmlElements)
                element.WriteTo(writer);

            writer.WriteEndElement();
        }

        public void WriteEntropy(XmlDictionaryWriter writer, WsSerializationContext serializationContext, Entropy entropy)
        {
            //  <wst:Entropy>
            //      <wst:BinarySecret>
            //          ...
            //      </wst:BinarySecret>
            //  </wst:Entropy>

            ValidateParamsForWritting(writer, serializationContext, entropy, nameof(entropy));
            writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.Entropy, serializationContext.TrustConstants.Namespace);
            if (entropy.BinarySecret != null)
            {
                writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.BinarySecret, serializationContext.TrustConstants.Namespace);
                if (!string.IsNullOrEmpty(entropy.BinarySecret.Type))
                    writer.WriteAttributeString(WsTrustAttributes.Type, entropy.BinarySecret.Type);

                writer.WriteBase64(entropy.BinarySecret.Data, 0, entropy.BinarySecret.Data.Length);
                writer.WriteEndElement();

            }

            writer.WriteEndElement();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="serializationContext"></param>
        /// <param name="policyReference"></param>
        public void WritePolicyReference(XmlDictionaryWriter writer, WsSerializationContext serializationContext, PolicyReference policyReference)
        {
            ValidateParamsForWritting(writer, serializationContext, policyReference, nameof(policyReference));
            writer.WriteStartElement(serializationContext.PolicyConstants.Prefix, WsPolicyElements.PolicyReference, serializationContext.PolicyConstants.Namespace);
            if (!string.IsNullOrEmpty(policyReference.Uri))
                writer.WriteAttributeString(WsPolicyAttributes.URI, policyReference.Uri);

            if (!string.IsNullOrEmpty(policyReference.Digest))
                writer.WriteAttributeString(WsPolicyAttributes.Digest, policyReference.Digest);

            if (!string.IsNullOrEmpty(policyReference.DigestAlgorithm))
                writer.WriteAttributeString(WsPolicyAttributes.DigestAlgorithm, policyReference.DigestAlgorithm);

            writer.WriteEndElement();
        }

        public void WriteRequestedSecurityToken(XmlDictionaryWriter writer, WsSerializationContext serializationContext, RequestedSecurityToken requestedSecurityToken)
        {
            ValidateParamsForWritting(writer, serializationContext, requestedSecurityToken, nameof(requestedSecurityToken));
            writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.RequestedSecurityToken, serializationContext.TrustConstants.Namespace);
            foreach (var tokenHandler in SecurityTokenHandlers)
            {
                if (tokenHandler.CanWriteSecurityToken(requestedSecurityToken.SecurityToken))
                {
                    if (!tokenHandler.TryWriteSourceData(writer, requestedSecurityToken.SecurityToken))
                        tokenHandler.WriteToken(writer, requestedSecurityToken.SecurityToken);

                    break;
                }
            }

            writer.WriteEndElement();
        }

        /// <summary>
        /// Checks standard items on a write call.
        /// </summary>
        /// <param name="writer">the <see cref="XmlWriter"/>to check.</param>
        /// <param name="context">the expected element.</param>
        /// <param name="obj"></param>
        /// <param name="objName"></param>
        internal static void ValidateParamsForWritting(XmlWriter writer, WsSerializationContext context, object obj, string objName)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (context == null)
                throw LogHelper.LogArgumentNullException(nameof(context));

            if (obj == null)
                throw LogHelper.LogArgumentNullException(objName);
        }

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
