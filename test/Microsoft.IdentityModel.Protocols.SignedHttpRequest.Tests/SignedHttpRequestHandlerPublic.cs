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
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest.Tests
{
    /// <summary>
    /// Mock SignedHttpRequestHandler.
    /// </summary>
    public class SignedHttpRequestHandlerPublic : SignedHttpRequestHandler
    {
        public string CreateHttpRequestHeaderPublic(SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            return CreateHttpRequestHeader(signedHttpRequestDescriptor);
        }

        public string CreateHttpRequestPayloadPublic(SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            return CreateHttpRequestPayload(signedHttpRequestDescriptor);
        }

        public async Task<string> SignHttpRequestPublicAsync(string header, string payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor, CancellationToken cancellationToken)
        {
            return await SignHttpRequestAsync(header, payload, signedHttpRequestDescriptor, cancellationToken).ConfigureAwait(false);
        }

        public string ConvertToJsonPublic(Dictionary<string, object> payload)
        {
            return ConvertToJson(payload);
        }

        public void AddAtClaimPublic(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            AddAtClaim(payload, signedHttpRequestDescriptor);
        }
   
        public void AddTsClaimPublic(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            AddTsClaim(payload, signedHttpRequestDescriptor);
        }

        public void AddMClaimPublic(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            AddMClaim(payload, signedHttpRequestDescriptor);
        }

        public void AddUClaimPublic(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            AddUClaim(payload, signedHttpRequestDescriptor);
        }

        public void AddPClaimPublic(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            AddPClaim(payload, signedHttpRequestDescriptor);
        }

        public void AddQClaimPublic(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            AddQClaim(payload, signedHttpRequestDescriptor);
        }
 
        public void AddHClaimPublic(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            AddHClaim(payload, signedHttpRequestDescriptor);
        }

        public void AddBClaimPublic(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            AddBClaim(payload, signedHttpRequestDescriptor);
        }

        public void AddNonceClaimPublic(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            AddNonceClaim(payload, signedHttpRequestDescriptor);
        }

        public void AddCnfClaimPublic(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            AddCnfClaim(payload, signedHttpRequestDescriptor);
        }

        public async Task<SecurityToken> ValidateSignedHttpRequestPublicAsync(JsonWebToken signedHttpRequest, SecurityKey popKey, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            return await ValidateSignedHttpRequestAsync(signedHttpRequest, popKey, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        public async Task<SecurityKey> ValidateSignedHttpRequestSignaturePublicAsync(JsonWebToken signedHttpRequest, SecurityKey popKey, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            return await ValidateSignatureAsync(signedHttpRequest, popKey, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        public void ValidateTsClaimPublic(JsonWebToken jwtSignedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            ValidateTsClaim(jwtSignedHttpRequest, signedHttpRequestValidationContext);
        }
    
        public void ValidateMClaimPublic(JsonWebToken jwtSignedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            ValidateMClaim(jwtSignedHttpRequest, signedHttpRequestValidationContext);
        }

        public void ValidateUClaimPublic(JsonWebToken jwtSignedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            ValidateUClaim(jwtSignedHttpRequest, signedHttpRequestValidationContext);
        }

        public void ValidatePClaimPublic(JsonWebToken jwtSignedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            ValidatePClaim(jwtSignedHttpRequest, signedHttpRequestValidationContext);
        }
  
        public void ValidateQClaimPublic(JsonWebToken jwtSignedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            ValidateQClaim(jwtSignedHttpRequest, signedHttpRequestValidationContext);
        }
       
        public void ValidateHClaimPublic(JsonWebToken jwtSignedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            ValidateHClaim(jwtSignedHttpRequest, signedHttpRequestValidationContext);
        }

        public void ValidateBClaimPublic(JsonWebToken jwtSignedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            ValidateBClaim(jwtSignedHttpRequest, signedHttpRequestValidationContext);
        }

        public async Task<SecurityKey> ResolvePopKeysPublicAsync(JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            return await ResolvePopKeyAsync(signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        public string GetCnfClaimValuePublic(JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            return GetCnfClaimValue(signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext);
        }

        public async Task<SecurityKey> ResolvePopKeyFromCnfClaimPublicAsync(string confirmationClaim, JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            return await ResolvePopKeyFromCnfClaimAsync(confirmationClaim, signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        public SecurityKey ResolvePopKeyFromJwkPublic(string jwk, JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            return ResolvePopKeyFromJwk(jwk, signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext);
        }

        public async Task<SecurityKey> ResolvePopKeyFromJwePublicAsync(string jwe, JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            return await ResolvePopKeyFromJweAsync(jwe, signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }
      
        public async Task<SecurityKey> ResolvePopKeyFromJkuPublicAsync(string jkuSetUrl, JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            return await ResolvePopKeyFromJkuAsync(jkuSetUrl, signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }
       
        public async Task<SecurityKey> ResolvePopKeyFromJkuPublicAsync(string jkuSetUrl, string kid, JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            return await ResolvePopKeyFromJkuAsync(jkuSetUrl, kid, signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        public async Task<SecurityKey> GetPopKeyFromJkuPublicAsync(string jkuSetUrl, JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            return await GetPopKeyFromJkuAsync(jkuSetUrl, signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        public async Task<SecurityKey> ResolvePopKeyFromKeyIdentifierPublicAsync(string kid, JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            return await ResolvePopKeyFromKeyIdentifierAsync(kid, signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        #region Mock methods
        protected override void AddTsClaim(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            if (signedHttpRequestDescriptor.CallContext.PropertyBag != null && signedHttpRequestDescriptor.CallContext.PropertyBag.TryGetValue("MockAddTsClaim", out object DateTimeNow))
            {
                if (payload == null)
                    throw LogHelper.LogArgumentNullException(nameof(payload));

                var signedHttpRequestCreationTime = ((DateTime)DateTimeNow).Add(signedHttpRequestDescriptor.SignedHttpRequestCreationParameters.TimeAdjustment);
                payload.Add(SignedHttpRequestClaimTypes.Ts, (long)(signedHttpRequestCreationTime - EpochTime.UnixEpoch).TotalSeconds);
            }
            else
            {
                base.AddTsClaim(payload, signedHttpRequestDescriptor);
            }
        }

        protected override void ValidateTsClaim(JsonWebToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("onlyTrack_ValidateTsClaimCall"))
                signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ValidateTsClaimCall"] = true;
            else
                base.ValidateTsClaim(signedHttpRequest, signedHttpRequestValidationContext);
        }

        protected override void ValidateMClaim(JsonWebToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("onlyTrack_ValidateMClaimCall"))
                signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ValidateMClaimCall"] = true;
            else
                base.ValidateMClaim(signedHttpRequest, signedHttpRequestValidationContext);
        }

        protected override void ValidatePClaim(JsonWebToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("onlyTrack_ValidatePClaimCall"))
                signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ValidatePClaimCall"] = true;
            else
                base.ValidatePClaim(signedHttpRequest, signedHttpRequestValidationContext);
        }

        protected override void ValidateUClaim(JsonWebToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("onlyTrack_ValidateUClaimCall"))
                signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ValidateUClaimCall"] = true;
            else
                base.ValidateUClaim(signedHttpRequest, signedHttpRequestValidationContext);
        }

        protected override void ValidateQClaim(JsonWebToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("onlyTrack_ValidateQClaimCall"))
                signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ValidateQClaimCall"] = true;
            else
                base.ValidateQClaim(signedHttpRequest, signedHttpRequestValidationContext);
        }

        protected override void ValidateHClaim(JsonWebToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("onlyTrack_ValidateHClaimCall"))
                signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ValidateHClaimCall"] = true;
            else
                base.ValidateHClaim(signedHttpRequest, signedHttpRequestValidationContext);
        }

        protected override void ValidateBClaim(JsonWebToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("onlyTrack_ValidateBClaimCall"))
                signedHttpRequestValidationContext.CallContext.PropertyBag["onlyTrack_ValidateBClaimCall"] = true;
            else
                base.ValidateBClaim(signedHttpRequest, signedHttpRequestValidationContext);
        }

        protected override async Task<SecurityKey> ValidateSignatureAsync(JsonWebToken signedHttpRequest, SecurityKey popKey, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockValidateSignedHttpRequestSignatureAsync"))
                return SignedHttpRequestTestUtils.DefaultSigningCredentials.Key;
            else
                return await base.ValidateSignatureAsync(signedHttpRequest, popKey, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        protected override async Task<SecurityKey> ResolvePopKeyAsync(JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockResolvePopKeyAsync_returnValidKey"))
            {
                return SignedHttpRequestTestUtils.DefaultSigningCredentials.Key;
            }
            else if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockResolvePopKeyAsync_returnInvalidKey"))
            {
                return KeyingMaterial.RsaSecurityKey1;
            }
            else if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockResolvePopKeyAsync_returnNullKey"))
            {
                return null;
            }
            else
            {
                return await base.ResolvePopKeyAsync(signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
            }
        }

        protected override async Task<TokenValidationResult> ValidateAccessTokenAsync(string accessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockValidateAccessTokenAsync_returnInvalidResult"))
            {
                return new TokenValidationResult()
                {
                    IsValid = false,
                    Exception = new SecurityTokenValidationException()
                };
            }
            else
            {
                return await base.ValidateAccessTokenAsync(accessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
            }
        }

        protected override string GetCnfClaimValue(JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (signedHttpRequestValidationContext?.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockGetCnfClaimValue_returnJwk"))
            {
                return SignedHttpRequestTestUtils.DefaultCnfJwk.ToString(Formatting.None);
            }
            else if (signedHttpRequestValidationContext?.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockGetCnfClaimValue_returnJwe"))
            {
                return SignedHttpRequestTestUtils.DefaultCnfJwe.ToString(Formatting.None);
            }
            else if (signedHttpRequestValidationContext?.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockGetCnfClaimValue_returnJku"))
            {
                return SignedHttpRequestTestUtils.DefaultJku.ToString(Formatting.None);
            }
            else if (signedHttpRequestValidationContext?.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockGetCnfClaimValue_returnJkuKid"))
            {
                return SignedHttpRequestTestUtils.DefaultJkuKid.ToString(Formatting.None);
            }
            else if (signedHttpRequestValidationContext?.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockGetCnfClaimValue_returnKid"))
            {
                return SignedHttpRequestTestUtils.DefaultKid.ToString(Formatting.None);
            }
            else if (signedHttpRequestValidationContext?.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockGetCnfClaimValue_returnCustom"))
            {
                return "{\"custom\": 1}";
            }
            else
            {
                return base.GetCnfClaimValue(signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext);
            }
        }

        protected override async Task<SecurityKey> ResolvePopKeyFromCnfClaimAsync(string confirmationClaim, JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationContext?.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockResolvePopKeyFromCnfClaimAsync_returnRsa"))
            {
                return signedHttpRequestValidationContext.CallContext.PropertyBag["mockResolvePopKeyFromCnfClaimAsync_returnRsa"] as RsaSecurityKey;
            }
            else
            {
                return await base.ResolvePopKeyFromCnfClaimAsync(confirmationClaim, signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
            }
        }

        protected override SecurityKey ResolvePopKeyFromJwk(string jwk, JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("trackResolvePopKeyFromJwk"))
            {
                signedHttpRequestValidationContext.CallContext.PropertyBag["trackResolvePopKeyFromJwk"] = true;
                return null;
            }

            return base.ResolvePopKeyFromJwk(jwk, signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext);  
        }

        protected override async Task<SecurityKey> ResolvePopKeyFromJweAsync(string jwe, JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("trackResolvePopKeyFromJwe"))
            {
                signedHttpRequestValidationContext.CallContext.PropertyBag["trackResolvePopKeyFromJwe"] = true;
                return null;
            }

            return await base.ResolvePopKeyFromJweAsync(jwe, signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        protected override async Task<SecurityKey> ResolvePopKeyFromJkuAsync(string jkuSetUrl, JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("trackResolvePopKeyFromJku"))
            {
                signedHttpRequestValidationContext.CallContext.PropertyBag["trackResolvePopKeyFromJku"] = true;
                return null;
            }

            return await base.ResolvePopKeyFromJkuAsync(jkuSetUrl, signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        protected override async Task<SecurityKey> ResolvePopKeyFromJkuAsync(string jkuSetUrl, string kid, JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("trackResolvePopKeyFromJkuKid"))
            {
                signedHttpRequestValidationContext.CallContext.PropertyBag["trackResolvePopKeyFromJkuKid"] = true;
                return null;
            }

            return await base.ResolvePopKeyFromJkuAsync(jkuSetUrl, kid, signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        protected override async Task<SecurityKey> ResolvePopKeyFromKeyIdentifierAsync(string kid, JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("trackResolvePopKeyFromKid"))
            {
                signedHttpRequestValidationContext.CallContext.PropertyBag["trackResolvePopKeyFromKid"] = true;
                return null;
            }

            return await base.ResolvePopKeyFromKeyIdentifierAsync(kid, signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        protected override async Task<SecurityKey> GetPopKeyFromJkuAsync(string jkuSetUrl, JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockGetPopKeysFromJkuAsync_returnNull"))
            {
                return null;
            }
            else if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockGetPopKeysFromJkuAsync_return2Keys"))
            {
                return SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key;
            }
            else if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockGetPopKeysFromJkuAsync_return1Key"))
            {
                return SignedHttpRequestTestUtils.DefaultSigningCredentials.Key;
            }
            else if (signedHttpRequestValidationContext.CallContext.PropertyBag != null && signedHttpRequestValidationContext.CallContext.PropertyBag.ContainsKey("mockGetPopKeysFromJkuAsync_returnWrongKey"))
            {
                return SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key;
            }

            return await base.GetPopKeyFromJkuAsync(jkuSetUrl, signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        #endregion
    }
}
