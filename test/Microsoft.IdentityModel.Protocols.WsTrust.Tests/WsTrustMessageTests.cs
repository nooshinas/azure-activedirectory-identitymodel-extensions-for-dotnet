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

using Microsoft.IdentityModel.Protocols.WsFed;
using Microsoft.IdentityModel.Protocols.WsPolicy;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Protocols.WsTrust.Tests
{
    public class WsTrustMessageTests
    {
        [Fact]
        public void ReadRequestSecurityTokenResponse()
        {
            var serializer = new WsTrustSerializer();
            var bytes = Encoding.UTF8.GetBytes(WsTrustReferenceXml.WsTrustResponseEncryptedToken);
            var reader = XmlDictionaryReader.CreateTextReader(bytes, XmlDictionaryReaderQuotas.Max);
            serializer.ReadRequestSecurityTokenResponse(reader);
        }

        [Fact]
        public void StringIntern()
        {
            TestUtilities.WriteHeader($"{this}.StringIntern");
            var context = new CompareContext("StringIntern");

            // WsTrustActions
            CheckRefs(context, "WsTrustFeb2005Actions.Cancel", (new WsTrustFeb2005Actions()).Cancel, WsTrustActions.TrustFeb2005.Cancel, WsTrustFeb2005Actions.Instance.Cancel);
            CheckRefs(context, "WsTrust13Actions.Cancel", (new WsTrust13Actions()).Cancel, WsTrustActions.Trust13.Cancel, WsTrust13Actions.Instance.Cancel);
            CheckRefs(context, "WsTrust14Actions.Cancel", (new WsTrust14Actions()).Cancel, WsTrustActions.Trust14.Cancel, WsTrust14Actions.Instance.Cancel);

            CheckRefs(context, "WsTrustFeb2005Actions.Issue", (new WsTrustFeb2005Actions()).Issue, WsTrustActions.TrustFeb2005.Issue, WsTrustFeb2005Actions.Instance.Issue);
            CheckRefs(context, "WsTrust13Actions.Issue", (new WsTrust13Actions()).Issue, WsTrustActions.Trust13.Issue, WsTrust13Actions.Instance.Issue);
            CheckRefs(context, "WsTrust14Actions.Issue", (new WsTrust14Actions()).Issue, WsTrustActions.Trust14.Issue, WsTrust14Actions.Instance.Issue);

            CheckRefs(context, "WsTrustFeb2005Actions.Validate", (new WsTrustFeb2005Actions()).Validate, WsTrustActions.TrustFeb2005.Validate, WsTrustFeb2005Actions.Instance.Validate);
            CheckRefs(context, "WsTrust13Actions.Validate", (new WsTrust13Actions()).Validate, WsTrustActions.Trust13.Validate, WsTrust13Actions.Instance.Validate);
            CheckRefs(context, "WsTrust14Actions.Validate", (new WsTrust14Actions()).Validate, WsTrustActions.Trust14.Validate, WsTrust14Actions.Instance.Validate);

            TestUtilities.AssertFailIfErrors(context);
        }

        private void CheckRefs(CompareContext context, string title, string string1, string string2, string string3)
        {
            if (!object.ReferenceEquals(string1, string2))
                context.AddDiff($"{title} : !object.ReferenceEquals(string1, string2)");

            if (!object.ReferenceEquals(string1, string3))
                context.AddDiff($"{title} : !object.ReferenceEquals(string1, string3)");

            if (!object.ReferenceEquals(string2, string3))
                context.AddDiff($"{title} : !object.ReferenceEquals(string2, string3)");
        }

        [Theory, MemberData(nameof(SerailizeWsTrustRequestTheoryData))]
        public void SerializeWsTrustRequest(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.SerializeWsTrustRequest", theoryData);

            try
            {
                var memeoryStream = new MemoryStream();
                var writer = XmlDictionaryWriter.CreateTextWriter(memeoryStream, Encoding.UTF8);
                var serializer = new WsTrustSerializer();
                var serializerContext = new WsSerializationContext(WsTrustVersion.Trust13);
                serializer.WriteRequest(writer, serializerContext, theoryData.WsTrustRequest);
                writer.Flush();
                var bytes = memeoryStream.ToArray();
                var xml = Encoding.UTF8.GetString(bytes);
                var reader = XmlDictionaryReader.CreateTextReader(bytes, XmlDictionaryReaderQuotas.Max);
                var trustRequest = serializer.ReadRequestSecurityToken(reader);
                IdentityComparer.AreEqual(trustRequest, theoryData.WsTrustRequest, context);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> SerailizeWsTrustRequestTheoryData
        {
            get
            {
                var contextItems = new List<ContextItem> { new ContextItem(Default.Uri, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()) };
                var additionalContext = new AdditionalContext(contextItems);
                var claims = new List<ClaimType> { new ClaimType { Uri = Guid.NewGuid().ToString(), IsOptional = true, Value = Guid.NewGuid().ToString() } };
                var requestClaims = new Claims(Guid.NewGuid().ToString(), claims);
                var tokenHandler = new Saml2SecurityTokenHandler();
                var tokenDescriptor = Default.SecurityTokenDescriptor(Default.AsymmetricSigningCredentials);
                var saml2Token = tokenHandler.CreateToken(tokenDescriptor);
                var token = tokenHandler.WriteToken(saml2Token);
                tokenHandler.ValidateToken(token, Default.TokenValidationParameters(Default.SymmetricEncryptionKey128, Default.AsymmetricSigningKey), out SecurityToken validatedToken);

                return new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData
                    {
                        First = true,
                        WsTrustRequest = new WsTrustRequest()
                        {
                            AdditionalContext = additionalContext,
                            AppliesTo = WsTrustMessageTestDefaults.AppliesTo,
                            CanonicalizationAlgorithm = SecurityAlgorithms.ExclusiveC14n,
                            Context = Guid.NewGuid().ToString(),
                            ComputedKeyAlgorithm = WsTrustKeyTypes.Trust13.PSHA1,
                            EncryptionAlgorithm = SecurityAlgorithms.Aes256Encryption,
                            EncryptWith = SecurityAlgorithms.Aes256Encryption,
                            PolicyReference = new PolicyReference(Default.Uri, SecurityAlgorithms.Sha256Digest, Guid.NewGuid().ToString()),
                            KeySizeInBits = 256,
                            KeyType = WsTrustKeyTypes.Trust13.PublicKey,
                            //OnBehalfOf = new SecurityTokenElement(validatedToken, tokenHandler),
                            Claims = requestClaims,
                            RequestType = WsTrustActions.Trust13.Issue,
                            SignWith = SecurityAlgorithms.Sha256Digest,
                            TokenType = Saml2Constants.OasisWssSaml2TokenProfile11
                        },
                        TestId = "SerializeWsTrustRequestTheoryData1"
                    }
                };
            }
        }
    }

    public class WsTrustTheoryData : TheoryDataBase
    {
        public object CompareTo { get; set; }

        public WsTrustRequest WsTrustRequest { get; set; }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
