﻿//------------------------------------------------------------------------------
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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Json;
using Microsoft.IdentityModel.Json.Linq;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest
{
    /// <summary>
    /// A handler designed for creating and validating signed http requests. 
    /// </summary>
    /// <remarks>The handler implementation is based on 'A Method for Signing HTTP Requests for OAuth' specification.</remarks>
    public class SignedHttpRequestHandler
    {
        // (https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3.2)
        // "Encodes the name and value of the header as "name: value" and appends it to the string buffer separated by a newline "\n" character."
        private readonly string _newlineSeparator = "\n";

        private readonly JsonWebTokenHandler _jwtTokenHandler = new JsonWebTokenHandler();
        private readonly Uri _baseUriHelper = new Uri("http://localhost", UriKind.Absolute);
        private readonly HttpClient _defaultHttpClient = new HttpClient();

        #region SignedHttpRequest creation
        /// <summary>
        /// Creates a signed http request using the <paramref name="signedHttpRequestDescriptor"/>.
        /// /// </summary>
        /// <param name="signedHttpRequestDescriptor">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A signed http request as a JWS in Compact Serialization Format.</returns>
        public async Task<string> CreateSignedHttpRequestAsync(SignedHttpRequestDescriptor signedHttpRequestDescriptor, CancellationToken cancellationToken)
        {
            if (signedHttpRequestDescriptor == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestDescriptor));

            var header = CreateHttpRequestHeader(signedHttpRequestDescriptor);
            var payload = CreateHttpRequestPayload(signedHttpRequestDescriptor);
            return await SignHttpRequestAsync(header, payload, signedHttpRequestDescriptor, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Creates a JSON representation of a HttpRequest header.
        /// </summary>
        /// <param name="signedHttpRequestDescriptor">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <returns>A JSON representation of an HttpRequest header.</returns>
        protected virtual string CreateHttpRequestHeader(SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            var header = new JObject
            {
                { JwtHeaderParameterNames.Alg, signedHttpRequestDescriptor.SigningCredentials.Algorithm },
                { JwtHeaderParameterNames.Typ, SignedHttpRequestConstants.TokenType }
            };

            if (signedHttpRequestDescriptor.SigningCredentials.Key is X509SecurityKey x509SecurityKey)
                header[JwtHeaderParameterNames.X5t] = x509SecurityKey.X5t;

            return header.ToString(Formatting.None);
        }

        /// <summary>
        /// Creates a JSON representation of a HttpRequest payload.
        /// </summary>
        /// <param name="signedHttpRequestDescriptor">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <returns>A JSON representation of an HttpRequest payload.</returns>
        /// <remarks>
        /// Users can utilize <see cref="SignedHttpRequestCreationParameters.AdditionalClaimCreator"/> to create additional claim(s) and add them to the signed http request.
        /// </remarks>
        private protected virtual string CreateHttpRequestPayload(SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            Dictionary<string, object> payload = new Dictionary<string, object>();

            AddAtClaim(payload, signedHttpRequestDescriptor);

            if (signedHttpRequestDescriptor.SignedHttpRequestCreationParameters.CreateTs)
                AddTsClaim(payload, signedHttpRequestDescriptor);

            if (signedHttpRequestDescriptor.SignedHttpRequestCreationParameters.CreateM)
                AddMClaim(payload, signedHttpRequestDescriptor);

            if (signedHttpRequestDescriptor.SignedHttpRequestCreationParameters.CreateU)
                AddUClaim(payload, signedHttpRequestDescriptor);

            if (signedHttpRequestDescriptor.SignedHttpRequestCreationParameters.CreateP)
                AddPClaim(payload, signedHttpRequestDescriptor);

            if (signedHttpRequestDescriptor.SignedHttpRequestCreationParameters.CreateQ)
                AddQClaim(payload, signedHttpRequestDescriptor);

            if (signedHttpRequestDescriptor.SignedHttpRequestCreationParameters.CreateH)
                AddHClaim(payload, signedHttpRequestDescriptor);

            if (signedHttpRequestDescriptor.SignedHttpRequestCreationParameters.CreateB)
                AddBClaim(payload, signedHttpRequestDescriptor);

            if (signedHttpRequestDescriptor.SignedHttpRequestCreationParameters.CreateNonce)
                AddNonceClaim(payload, signedHttpRequestDescriptor);

            if (signedHttpRequestDescriptor.SignedHttpRequestCreationParameters.CreateCnf)
                AddCnfClaim(payload, signedHttpRequestDescriptor);

            signedHttpRequestDescriptor.SignedHttpRequestCreationParameters.AdditionalClaimCreator?.Invoke(payload, signedHttpRequestDescriptor);

            return ConvertToJson(payload);
        }

        /// <summary>
        /// Converts a dictionary representation of HttpRequest into a JSON string.
        /// </summary>
        /// <param name="payload">HttpRequest payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <returns>A JSON string.</returns>
        protected virtual string ConvertToJson(Dictionary<string, object> payload)
        {
            return JObject.FromObject(payload).ToString(Formatting.None);
        }

        /// <summary>
        /// Encodes and signs a http request message (<paramref name="header"/>, <paramref name="payload"/>) using the <see cref="SignedHttpRequestDescriptor.SigningCredentials"/>.
        /// </summary>
        /// <param name="header">A JSON representation of a HttpRequest header.</param>
        /// <param name="payload">A JSON representation of a HttpRequest payload.</param>
        /// <param name="signedHttpRequestDescriptor">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>SignedHttpRequest as a JWS in Compact Serialization Format.</returns>
        protected virtual Task<string> SignHttpRequestAsync(string header, string payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(header))
                throw LogHelper.LogArgumentNullException(nameof(header));

            if (string.IsNullOrEmpty(payload))
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var message = $"{Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header))}.{Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload))}";
            var signature = JwtTokenUtilities.CreateEncodedSignature(message, signedHttpRequestDescriptor.SigningCredentials);
            return Task.FromResult($"{message}.{signature}");
        }

        /// <summary>
        /// Adds the 'at' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">HttpRequest payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="signedHttpRequestDescriptor">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        protected virtual void AddAtClaim(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            payload.Add(SignedHttpRequestClaimTypes.At, signedHttpRequestDescriptor.AccessToken);
        }

        /// <summary>
        /// Adds the 'ts' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">HttpRequest payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="signedHttpRequestDescriptor">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestCreationParameters.CreateTs"/> is set to <c>true</c>.
        /// </remarks>    
        protected virtual void AddTsClaim(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var signedHttpRequestCreationTime = DateTime.UtcNow.Add(signedHttpRequestDescriptor.SignedHttpRequestCreationParameters.TimeAdjustment);
            payload.Add(SignedHttpRequestClaimTypes.Ts, (long)(signedHttpRequestCreationTime - EpochTime.UnixEpoch).TotalSeconds);
        }

        /// <summary>
        /// Adds the 'm' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">HttpRequest payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="signedHttpRequestDescriptor">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestCreationParameters.CreateM"/> is set to <c>true</c>.
        /// </remarks>   
        protected virtual void AddMClaim(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var httpMethod = signedHttpRequestDescriptor.HttpRequestData.Method;

            if (string.IsNullOrEmpty(httpMethod))
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestDescriptor.HttpRequestData.Method));

            if (!httpMethod.ToUpper().Equals(httpMethod, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestCreationException(LogHelper.FormatInvariant(LogMessages.IDX23002, httpMethod)));

            payload.Add(SignedHttpRequestClaimTypes.M, httpMethod);
        }

        /// <summary>
        /// Adds the 'u' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">HttpRequest payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="signedHttpRequestDescriptor">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestCreationParameters.CreateU"/> is set to <c>true</c>.
        /// </remarks>  
        protected virtual void AddUClaim(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var httpRequestUri = signedHttpRequestDescriptor.HttpRequestData.Uri;

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestDescriptor.HttpRequestData.Uri));

            if (!httpRequestUri.IsAbsoluteUri)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestCreationException(LogHelper.FormatInvariant(LogMessages.IDX23001, httpRequestUri.ToString())));

            // https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3
            // u claim: The HTTP URL host component as a JSON string. This MAY include the port separated from the host by a colon in host:port format.
            // Including the port if it not the default port for the httpRequestUri scheme.
            var httpUrlHostComponent = httpRequestUri.Host;
            if (!httpRequestUri.IsDefaultPort)
                httpUrlHostComponent = $"{httpUrlHostComponent}:{httpRequestUri.Port}";

            payload.Add(SignedHttpRequestClaimTypes.U, httpUrlHostComponent);
        }

        /// <summary>
        /// Adds the 'm' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">HttpRequest payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="signedHttpRequestDescriptor">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestCreationParameters.CreateP"/> is set to <c>true</c>.
        /// </remarks>  
        protected virtual void AddPClaim(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var httpRequestUri = signedHttpRequestDescriptor.HttpRequestData.Uri;

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestDescriptor.HttpRequestData.Uri));

            httpRequestUri = EnsureAbsoluteUri(httpRequestUri);

            payload.Add(SignedHttpRequestClaimTypes.P, httpRequestUri.AbsolutePath);
        }

        /// <summary>
        /// Adds the 'q' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">HttpRequest payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="signedHttpRequestDescriptor">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestCreationParameters.CreateQ"/> is set to <c>true</c>.
        /// </remarks>  
        protected virtual void AddQClaim(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var httpRequestUri = signedHttpRequestDescriptor.HttpRequestData.Uri;

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestDescriptor.HttpRequestData.Uri));

            httpRequestUri = EnsureAbsoluteUri(httpRequestUri);
            var sanitizedQueryParams = SanitizeQueryParams(httpRequestUri);

            StringBuilder stringBuffer = new StringBuilder();
            List<string> queryParamNameList = new List<string>();
            try
            {
                var lastQueryParam = sanitizedQueryParams.LastOrDefault();
                foreach (var queryParam in sanitizedQueryParams)
                {
                    queryParamNameList.Add(queryParam.Key);
                    var encodedValue = $"{queryParam.Key}={queryParam.Value}";

                    if (!queryParam.Equals(lastQueryParam))
                        encodedValue += "&";

                    stringBuffer.Append(encodedValue);
                }

                var base64UrlEncodedHash = CalculateBase64UrlEncodedHash(stringBuffer.ToString());
                payload.Add(SignedHttpRequestClaimTypes.Q, new List<object>() { queryParamNameList, base64UrlEncodedHash });
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestCreationException(LogHelper.FormatInvariant(LogMessages.IDX23008, SignedHttpRequestClaimTypes.Q, e), e));
            }
        }

        /// <summary>
        /// Adds the 'h' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">HttpRequest payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="signedHttpRequestDescriptor">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestCreationParameters.CreateH"/> is set to <c>true</c>.
        /// </remarks>  
        protected virtual void AddHClaim(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (signedHttpRequestDescriptor.HttpRequestData.Headers == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestDescriptor.HttpRequestData.Headers));

            var sanitizedHeaders = SanitizeHeaders(signedHttpRequestDescriptor.HttpRequestData.Headers);
            StringBuilder stringBuffer = new StringBuilder();
            List<string> headerNameList = new List<string>();
            try
            {
                var lastHeader = sanitizedHeaders.LastOrDefault();
                foreach (var header in sanitizedHeaders)
                {
                    var headerName = header.Key.ToLower();
                    headerNameList.Add(headerName);

                    var encodedValue = $"{headerName}: {header.Value}";
                    if (header.Equals(lastHeader))
                        stringBuffer.Append(encodedValue);
                    else
                        stringBuffer.Append(encodedValue + _newlineSeparator);
                }

                var base64UrlEncodedHash = CalculateBase64UrlEncodedHash(stringBuffer.ToString());
                payload.Add(SignedHttpRequestClaimTypes.H, new List<object>() { headerNameList, base64UrlEncodedHash });
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestCreationException(LogHelper.FormatInvariant(LogMessages.IDX23008, SignedHttpRequestClaimTypes.H, e), e));
            }
        }

        /// <summary>
        /// Adds the 'b' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">HttpRequest payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="signedHttpRequestDescriptor">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestCreationParameters.CreateB"/> is set to <c>true</c>.
        /// </remarks> 
        protected virtual void AddBClaim(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            var httpRequestBody = signedHttpRequestDescriptor.HttpRequestData.Body;

            if (httpRequestBody == null)
                httpRequestBody = new byte[0];

            try
            {
                var base64UrlEncodedHash = CalculateBase64UrlEncodedHash(httpRequestBody);
                payload.Add(SignedHttpRequestClaimTypes.B, base64UrlEncodedHash);
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestCreationException(LogHelper.FormatInvariant(LogMessages.IDX23008, SignedHttpRequestClaimTypes.B, e), e));
            }
        }

        /// <summary>
        /// Adds the 'nonce' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">HttpRequest payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="signedHttpRequestDescriptor">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestCreationParameters.CreateNonce"/> is set to <c>true</c>.
        /// Users can utilize <see cref="SignedHttpRequestCreationParameters.CustomNonceCreator"/> to override the default behavior.
        /// </remarks>
        protected virtual void AddNonceClaim(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (signedHttpRequestDescriptor.SignedHttpRequestCreationParameters.CustomNonceCreator != null)
                signedHttpRequestDescriptor.SignedHttpRequestCreationParameters.CustomNonceCreator(payload, signedHttpRequestDescriptor);
            else
                payload.Add(SignedHttpRequestClaimTypes.Nonce, Guid.NewGuid().ToString("N"));
        }

        /// <summary>
        /// Adds the 'cnf' claim to the <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">HttpRequest payload represented as a <see cref="Dictionary{TKey, TValue}"/>.</param>
        /// <param name="signedHttpRequestDescriptor">A structure that wraps parameters needed for SignedHttpRequest creation.</param>
        /// <remarks>
        /// If <see cref="SignedHttpRequestDescriptor.CnfClaimValue"/> is not null or empty, its value will be used as a "cnf" claim value.
        /// Otherwise, a "cnf" claim value will be derived from the <see cref="SigningCredentials"/>.<see cref="SecurityKey"/> member of <paramref name="signedHttpRequestDescriptor"/>.
        /// </remarks>
        protected virtual void AddCnfClaim(Dictionary<string, object> payload, SignedHttpRequestDescriptor signedHttpRequestDescriptor)
        {
            if (payload == null)
                throw LogHelper.LogArgumentNullException(nameof(payload));
            try
            {
                if (!string.IsNullOrEmpty(signedHttpRequestDescriptor.CnfClaimValue))
                {
                    payload.Add(SignedHttpRequestClaimTypes.Cnf, JObject.Parse(signedHttpRequestDescriptor.CnfClaimValue));
                }
                else
                {
                    var signedHttpRequestSigningKey = signedHttpRequestDescriptor.SigningCredentials.Key;
                    JsonWebKey jsonWebKey;
                    if (signedHttpRequestSigningKey is JsonWebKey jwk)
                        jsonWebKey = jwk;
                    // create a JsonWebKey from an X509SecurityKey, represented as an RsaSecurityKey. 
                    else if (signedHttpRequestSigningKey is X509SecurityKey x509SecurityKey)
                        jsonWebKey = JsonWebKeyConverter.ConvertFromX509SecurityKey(x509SecurityKey, true);
                    else if (signedHttpRequestSigningKey is AsymmetricSecurityKey asymmetricSecurityKey)
                        jsonWebKey = JsonWebKeyConverter.ConvertFromSecurityKey(asymmetricSecurityKey);
                    else
                        throw LogHelper.LogExceptionMessage(new SignedHttpRequestCreationException(LogHelper.FormatInvariant(LogMessages.IDX23033, signedHttpRequestSigningKey != null ? signedHttpRequestSigningKey.GetType().ToString() : "null")));
                    
                    // set the jwk thumbprint as the Kid
                    jsonWebKey.Kid = Base64UrlEncoder.Encode(jsonWebKey.ComputeJwkThumbprint());
                    payload.Add(SignedHttpRequestClaimTypes.Cnf, JObject.Parse(SignedHttpRequestUtilities.CreateJwkClaim(jsonWebKey)));
                }
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestCreationException(LogHelper.FormatInvariant(LogMessages.IDX23008, SignedHttpRequestClaimTypes.Cnf, e), e));
            }
        }
        #endregion

        #region SignedHttpRequest validation
        /// <summary>
        /// Validates a signed http request using the <paramref name="signedHttpRequestValidationContext"/>.
        /// </summary>
        /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A <see cref="SignedHttpRequestValidationResult"/>. 
        /// <see cref="TokenValidationResult.IsValid"/> will be <c>true</c> if the signed http request was successfully validated, <c>false</c> otherwise.
        /// </returns>
        public async Task<SignedHttpRequestValidationResult> ValidateSignedHttpRequestAsync(SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            try
            {
                if (signedHttpRequestValidationContext == null)
                    throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestValidationContext));

                // read signed http request as JWT
                var signedHttpRequest = _jwtTokenHandler.ReadJsonWebToken(signedHttpRequestValidationContext.SignedHttpRequest);

                // read access token ("at")
                if (!signedHttpRequest.TryGetPayloadValue(SignedHttpRequestClaimTypes.At, out string accessToken) || string.IsNullOrEmpty(accessToken))
                    throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidAtClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, SignedHttpRequestClaimTypes.At)));

                // validate access token ("at")
                var tokenValidationResult = await ValidateAccessTokenAsync(accessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
                if (!tokenValidationResult.IsValid)
                    throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidAtClaimException(LogHelper.FormatInvariant(LogMessages.IDX23013, tokenValidationResult.Exception), tokenValidationResult.Exception));

                // resolve PoP keys (confirmation keys)
                var popKey = await ResolvePopKeyAsync(signedHttpRequest, tokenValidationResult.SecurityToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);

                // validate signed http request
                var validatedSignedHttpRequest = await ValidateSignedHttpRequestAsync(signedHttpRequest, popKey, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);

                return new SignedHttpRequestValidationResult()
                {
                    IsValid = true,
                    AccessToken = accessToken,
                    ClaimsIdentity = tokenValidationResult.ClaimsIdentity,
                    SecurityToken = tokenValidationResult.SecurityToken,
                    SignedHttpRequest = signedHttpRequest.EncodedToken,
                    ValidatedSignedHttpRequest = validatedSignedHttpRequest
                };
            }
            catch (Exception ex)
            {
                return new SignedHttpRequestValidationResult()
                {
                    IsValid = false,
                    Exception = ex
                };
            }
        }

        /// <summary>
        /// Validates an access token ("at").
        /// </summary>
        /// <param name="accessToken">An access token ("at") as a JWT.</param>
        /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A <see cref="TokenValidationResult"/>.</returns>
        protected virtual Task<TokenValidationResult> ValidateAccessTokenAsync(string accessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(accessToken))
                throw LogHelper.LogArgumentNullException(nameof(accessToken));

            var tokenValidationResult = _jwtTokenHandler.ValidateToken(accessToken, signedHttpRequestValidationContext.AccessTokenValidationParameters);
            return Task.FromResult(tokenValidationResult);
        }

        /// <summary>
        /// Validates signed http request.
        /// </summary>
        /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
        /// <param name="popKey">A collection of pop keys used to validate signature of the signed http request.</param>
        /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns></returns>
        /// <remarks>
        /// The library doesn't provide any caching logic for replay validation purposes.
        /// <see cref="SignedHttpRequestValidationParameters.ReplayValidatorAsync"/> delegate can be utilized for replay validation.
        /// Users can utilize <see cref="SignedHttpRequestValidationParameters.AdditionalClaimValidatorAsync"/> to validate additional signed http request claim(s).
        /// </remarks>
        private protected virtual async Task<SecurityToken> ValidateSignedHttpRequestAsync(JsonWebToken signedHttpRequest, SecurityKey popKey, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ReplayValidatorAsync != null)
                await signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ReplayValidatorAsync(signedHttpRequest, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);

            signedHttpRequest.SigningKey = await ValidateSignatureAsync(signedHttpRequest, popKey, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);

            if (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ValidateTs)
                ValidateTsClaim(signedHttpRequest, signedHttpRequestValidationContext);

            if (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ValidateM)
                ValidateMClaim(signedHttpRequest, signedHttpRequestValidationContext);

            if (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ValidateU)
                ValidateUClaim(signedHttpRequest, signedHttpRequestValidationContext);

            if (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ValidateP)
                ValidatePClaim(signedHttpRequest, signedHttpRequestValidationContext);

            if (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ValidateQ)
                ValidateQClaim(signedHttpRequest, signedHttpRequestValidationContext);

            if (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ValidateH)
                ValidateHClaim(signedHttpRequest, signedHttpRequestValidationContext);

            if (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.ValidateB)
                ValidateBClaim(signedHttpRequest, signedHttpRequestValidationContext);

            if (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.AdditionalClaimValidatorAsync != null)
                await signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.AdditionalClaimValidatorAsync(signedHttpRequest, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);

            return signedHttpRequest;
        }

        /// <summary>
        /// Validates the signature of the signed http request using <paramref name="popKey"/>.
        /// </summary>
        /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
        /// <param name="popKey">A collection of Pop keys used to validate the signed http request signature.</param>
        /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A PoP <see cref="SecurityKey"/> that validates signature of the <paramref name="signedHttpRequest"/>.</returns>
        protected virtual async Task<SecurityKey> ValidateSignatureAsync(JsonWebToken signedHttpRequest, SecurityKey popKey, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (signedHttpRequest == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequest));

            if (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.SignatureValidatorAsync != null)
                return await signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.SignatureValidatorAsync(popKey, signedHttpRequest, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);

            if (popKey == null)
                throw LogHelper.LogArgumentNullException(nameof(popKey));

            var exceptionStrings = new StringBuilder();

            try
            {
                if (_jwtTokenHandler.ValidateSignature(Encoding.UTF8.GetBytes(signedHttpRequest.EncodedHeader + "." + signedHttpRequest.EncodedPayload), Base64UrlEncoder.DecodeBytes(signedHttpRequest.EncodedSignature), popKey, signedHttpRequest.Alg, new TokenValidationParameters()))
                    return popKey;
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidSignatureException(LogHelper.FormatInvariant(LogMessages.IDX23009, ex.ToString()), ex));
            }

            throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidSignatureException(LogHelper.FormatInvariant(LogMessages.IDX23035, signedHttpRequest.EncodedHeader + "." + signedHttpRequest.EncodedPayload)));
        }

        /// <summary>
        /// Validates the signed http request lifetime ("ts").
        /// </summary>
        /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
        /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestValidationParameters.ValidateTs"/> is set to <c>true</c>.
        /// </remarks>    
        protected virtual void ValidateTsClaim(JsonWebToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (signedHttpRequest == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequest));

            if (!signedHttpRequest.TryGetPayloadValue(SignedHttpRequestClaimTypes.Ts, out long tsClaimValue))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidTsClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, SignedHttpRequestClaimTypes.Ts)));

            DateTime utcNow = DateTime.UtcNow;
            DateTime signedHttpRequestCreationTime = EpochTime.DateTime(tsClaimValue);
            DateTime signedHttpRequestExpirationTime = signedHttpRequestCreationTime.Add(signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.SignedHttpRequestLifetime);

            if (utcNow > signedHttpRequestExpirationTime)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidTsClaimException(LogHelper.FormatInvariant(LogMessages.IDX23010, utcNow, signedHttpRequestExpirationTime)));
        }

        /// <summary>
        /// Validates the signed http request "m" claim.
        /// </summary>
        /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
        /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestValidationParameters.ValidateM"/> is set to <c>true</c>.
        /// </remarks>     
        protected virtual void ValidateMClaim(JsonWebToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (signedHttpRequest == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequest));

            var expectedHttpMethod = signedHttpRequestValidationContext.HttpRequestData.Method;

            if (signedHttpRequest == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequest));

            if (string.IsNullOrEmpty(expectedHttpMethod))
                throw LogHelper.LogArgumentNullException(nameof(expectedHttpMethod));

            if (!signedHttpRequest.TryGetPayloadValue(SignedHttpRequestClaimTypes.M, out string httpMethod) || httpMethod == null)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidMClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, SignedHttpRequestClaimTypes.M)));

            // "get " is functionally the same as "GET".
            // different implementations might use differently formatted http verbs and we shouldn't fault.
            httpMethod = httpMethod.Trim();
            expectedHttpMethod = expectedHttpMethod.Trim();
            if (!string.Equals(expectedHttpMethod, httpMethod, StringComparison.OrdinalIgnoreCase))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidMClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, SignedHttpRequestClaimTypes.M, expectedHttpMethod, httpMethod)));
        }

        /// <summary>
        /// Validates the signed http request "u" claim. 
        /// </summary>
        /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
        /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestValidationParameters.ValidateU"/> is set to <c>true</c>.
        /// </remarks>     
        protected virtual void ValidateUClaim(JsonWebToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (signedHttpRequest == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequest));

            var httpRequestUri = signedHttpRequestValidationContext.HttpRequestData.Uri;
            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestValidationContext.HttpRequestData.Uri));

            if (!httpRequestUri.IsAbsoluteUri)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidUClaimException(LogHelper.FormatInvariant(LogMessages.IDX23001, httpRequestUri.ToString())));

            if (!signedHttpRequest.TryGetPayloadValue(SignedHttpRequestClaimTypes.U, out string uClaimValue) || uClaimValue == null)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidUClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, SignedHttpRequestClaimTypes.U)));

            // https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3.2
            // u: The HTTP URL host component as a JSON string.
            // This MAY include the port separated from the host by a colon in host:port format.
            var expectedUClaimValue = httpRequestUri.Host;
            var expectedUClaimValueIncludingPort = $"{expectedUClaimValue}:{httpRequestUri.Port}";

            if (!string.Equals(expectedUClaimValue, uClaimValue, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(expectedUClaimValueIncludingPort, uClaimValue, StringComparison.OrdinalIgnoreCase))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidUClaimException(LogHelper.FormatInvariant(LogMessages.IDX23012, SignedHttpRequestClaimTypes.U, expectedUClaimValue, expectedUClaimValueIncludingPort, uClaimValue)));
        }

        /// <summary>
        /// Validates the signed http request "p" claim. 
        /// </summary>
        /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
        /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestValidationParameters.ValidateP"/> is set to <c>true</c>.
        /// </remarks>     
        protected virtual void ValidatePClaim(JsonWebToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            var httpRequestUri = signedHttpRequestValidationContext.HttpRequestData.Uri;

            if (signedHttpRequest == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequest));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestValidationContext.HttpRequestData.Uri));

            httpRequestUri = EnsureAbsoluteUri(httpRequestUri);
            if (!signedHttpRequest.TryGetPayloadValue(SignedHttpRequestClaimTypes.P, out string pClaimValue) || pClaimValue == null)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, SignedHttpRequestClaimTypes.P)));

            // relax comparison by trimming start and ending forward slashes
            pClaimValue = pClaimValue.Trim('/');
            var expectedPClaimValue = httpRequestUri.AbsolutePath.Trim('/');

            if (!string.Equals(expectedPClaimValue, pClaimValue, StringComparison.OrdinalIgnoreCase))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, SignedHttpRequestClaimTypes.P, expectedPClaimValue, pClaimValue)));
        }

        /// <summary>
        /// Validates the signed http request "q" claim. 
        /// </summary>
        /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
        /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestValidationParameters.ValidateQ"/> is set to <c>true</c>.
        /// </remarks>     
        protected virtual void ValidateQClaim(JsonWebToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            var httpRequestUri = signedHttpRequestValidationContext.HttpRequestData.Uri;

            if (signedHttpRequest == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequest));

            if (httpRequestUri == null)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestUri));

            if (!signedHttpRequest.TryGetPayloadValue(SignedHttpRequestClaimTypes.Q, out JArray qClaim) || qClaim == null)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, SignedHttpRequestClaimTypes.Q)));

            httpRequestUri = EnsureAbsoluteUri(httpRequestUri);
            var sanitizedQueryParams = SanitizeQueryParams(httpRequestUri);

            string qClaimBase64UrlEncodedHash = string.Empty;
            string expectedBase64UrlEncodedHash = string.Empty;
            List<string> qClaimQueryParamNames;
            try
            {
                // "q": [["queryParamName1", "queryParamName2",... "queryParamNameN"], "base64UrlEncodedHashValue"]]
                qClaimQueryParamNames = qClaim[0].ToObject<List<string>>();
                qClaimBase64UrlEncodedHash = qClaim[1].ToString();
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23024, SignedHttpRequestClaimTypes.Q, qClaim.ToString(), e), e));
            }

            try
            {
                StringBuilder stringBuffer = new StringBuilder();
                var lastQueryParam = qClaimQueryParamNames.LastOrDefault();
                foreach (var queryParamName in qClaimQueryParamNames)
                {
                    if (!sanitizedQueryParams.TryGetValue(queryParamName, out var queryParamsValue))
                    {
                        throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23028, queryParamName, string.Join(", ", sanitizedQueryParams.Select(x => x.Key)))));
                    }
                    else
                    {
                        var encodedValue = $"{queryParamName}={queryParamsValue}";

                        if (!queryParamName.Equals(lastQueryParam))
                            encodedValue += "&";

                        stringBuffer.Append(encodedValue);

                        // remove the query param from the dictionary to mark it as covered.
                        sanitizedQueryParams.Remove(queryParamName);
                    }
                }

                expectedBase64UrlEncodedHash = CalculateBase64UrlEncodedHash(stringBuffer.ToString());
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23025, SignedHttpRequestClaimTypes.Q, e), e));
            }

            if (!signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.AcceptUnsignedQueryParameters && sanitizedQueryParams.Any())
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23029, string.Join(", ", sanitizedQueryParams.Select(x => x.Key)))));

            if (!string.Equals(expectedBase64UrlEncodedHash, qClaimBase64UrlEncodedHash, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidQClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, SignedHttpRequestClaimTypes.Q, expectedBase64UrlEncodedHash, qClaimBase64UrlEncodedHash)));
        }

        /// <summary>
        /// Validates the signed http request "h" claim. 
        /// </summary>
        /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
        /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestValidationParameters.ValidateH"/> is set to <c>true</c>.
        /// </remarks>     
        protected virtual void ValidateHClaim(JsonWebToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            var httpRequestHeaders = signedHttpRequestValidationContext.HttpRequestData.Headers;

            if (signedHttpRequest == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequest));

            if (httpRequestHeaders == null)
                throw LogHelper.LogArgumentNullException(nameof(httpRequestHeaders));

            if (!signedHttpRequest.TryGetPayloadValue(SignedHttpRequestClaimTypes.H, out JArray hClaim) || hClaim == null)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, SignedHttpRequestClaimTypes.H)));

            var sanitizedHeaders = SanitizeHeaders(httpRequestHeaders);

            string hClaimBase64UrlEncodedHash = string.Empty;
            string expectedBase64UrlEncodedHash = string.Empty;
            List<string> hClaimHeaderNames;
            try
            {
                // "h": [["headerName1", "headerName2",... "headerNameN"], "base64UrlEncodedHashValue"]]
                hClaimHeaderNames = hClaim[0].ToObject<List<string>>();
                hClaimBase64UrlEncodedHash = hClaim[1].ToString();
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23024, SignedHttpRequestClaimTypes.H, hClaim.ToString(), e), e));
            }

            try
            {
                StringBuilder stringBuffer = new StringBuilder();
                var lastHeader = hClaimHeaderNames.LastOrDefault();
                foreach (var headerName in hClaimHeaderNames)
                {
                    if (!sanitizedHeaders.TryGetValue(headerName, out var headerValue))
                    {
                        throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23027, headerName, string.Join(", ", sanitizedHeaders.Select(x => x.Key)))));
                    }
                    else
                    {
                        var encodedValue = $"{headerName}: {headerValue}";
                        if (headerName.Equals(lastHeader))
                            stringBuffer.Append(encodedValue);
                        else
                            stringBuffer.Append(encodedValue + _newlineSeparator);

                        // remove the header from the dictionary to mark it as covered.
                        sanitizedHeaders.Remove(headerName);
                    }
                }

                expectedBase64UrlEncodedHash = CalculateBase64UrlEncodedHash(stringBuffer.ToString());
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23025, SignedHttpRequestClaimTypes.H, e), e));
            }

            if (!signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.AcceptUnsignedHeaders && sanitizedHeaders.Any())
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23026, string.Join(", ", sanitizedHeaders.Select(x => x.Key)))));

            if (!string.Equals(expectedBase64UrlEncodedHash, hClaimBase64UrlEncodedHash, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidHClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, SignedHttpRequestClaimTypes.H, expectedBase64UrlEncodedHash, hClaimBase64UrlEncodedHash)));
        }

        /// <summary>
        /// Validates the signed http request "b" claim. 
        /// </summary>
        /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
        /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <remarks>
        /// This method will be executed only if <see cref="SignedHttpRequestValidationParameters.ValidateB"/> is set to <c>true</c>.
        /// </remarks>     
        protected virtual void ValidateBClaim(JsonWebToken signedHttpRequest, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            var httpRequestBody = signedHttpRequestValidationContext.HttpRequestData.Body;

            if (signedHttpRequest == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequest));

            if (httpRequestBody == null)
                httpRequestBody = new byte[0];

            if (!signedHttpRequest.TryGetPayloadValue(SignedHttpRequestClaimTypes.B, out string bClaim) || bClaim == null)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidBClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, SignedHttpRequestClaimTypes.B)));

            string expectedBase64UrlEncodedHash;
            try
            {
                expectedBase64UrlEncodedHash = CalculateBase64UrlEncodedHash(httpRequestBody);
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestCreationException(LogHelper.FormatInvariant(LogMessages.IDX23008, SignedHttpRequestClaimTypes.B, e), e));
            }

            if (!string.Equals(expectedBase64UrlEncodedHash, bClaim, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidBClaimException(LogHelper.FormatInvariant(LogMessages.IDX23011, SignedHttpRequestClaimTypes.B, expectedBase64UrlEncodedHash, bClaim)));
        }
        #endregion

        #region Resolving PoP key
        /// <summary>
        /// Resolves a collection of PoP <see cref="SecurityKey"/>(s).
        /// </summary>
        /// <param name="signedHttpRequest">A signed http request as a JWT.</param>
        /// <param name="validatedAccessToken">An access token ("at") that was already validated during the SignedHttpRequest validation process.</param>
        /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
        protected virtual async Task<SecurityKey> ResolvePopKeyAsync(JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationContext == null)
                throw LogHelper.LogArgumentNullException(nameof(signedHttpRequestValidationContext));

            if (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.PopKeyResolverAsync != null)
                return await signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.PopKeyResolverAsync(signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);

            var cnf = GetCnfClaimValue(signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext);
            return await ResolvePopKeyFromCnfClaimAsync(cnf, signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Gets the JSON representation of the 'cnf' claim.
        /// This method expects a "cnf" claim to be present as a claim of the <paramref name="validatedAccessToken"/> ("at").
        /// </summary>
        /// <param name="signedHttpRequest">A signed http request as a JWT.</param>
        /// <param name="validatedAccessToken">An access token ("at") that was already validated during the SignedHttpRequest validation process.</param>
        /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <returns>JSON representation of the 'cnf' claim.</returns>
        protected virtual string GetCnfClaimValue(JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (validatedAccessToken == null)
                throw LogHelper.LogArgumentNullException(nameof(validatedAccessToken));

            if (!(validatedAccessToken is JsonWebToken jwtValidatedAccessToken))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestValidationException(LogHelper.FormatInvariant(LogMessages.IDX23031, validatedAccessToken.GetType(), typeof(JsonWebToken), validatedAccessToken)));

            // use the decrypted jwt if the jwtValidatedAccessToken is encrypted.
            // [brentsch] - does this always imply that this is a jwe
            if (jwtValidatedAccessToken.InnerToken != null)
                jwtValidatedAccessToken = jwtValidatedAccessToken.InnerToken;

            if (jwtValidatedAccessToken.TryGetPayloadValue(ConfirmationClaimTypes.Cnf, out JObject cnf) && cnf != null)
                return cnf.ToString(Formatting.None);
            else
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidCnfClaimException(LogHelper.FormatInvariant(LogMessages.IDX23003, ConfirmationClaimTypes.Cnf)));
        }

        /// <summary>
        /// Resolves a PoP <see cref="SecurityKey"/> from a confirmation ("cnf") claim.
        /// </summary>
        /// <param name="confirmationClaim">A confirmation ("cnf") claim as a string.</param>
        /// <param name="signedHttpRequest">A signed http request as a JWT.</param>
        /// <param name="validatedAccessToken">An access token ("at") that was already validated during the SignedHttpRequest validation process.</param>
        /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
        /// <remarks>https://tools.ietf.org/html/rfc7800#section-3.1</remarks>
        protected virtual async Task<SecurityKey> ResolvePopKeyFromCnfClaimAsync(string confirmationClaim, JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(confirmationClaim))
                throw LogHelper.LogArgumentNullException(nameof(confirmationClaim));

            var cnf = JObject.Parse(confirmationClaim);
            if (cnf.TryGetValue(ConfirmationClaimTypes.Jwk, StringComparison.Ordinal, out var jwk))
                return ResolvePopKeyFromJwk(jwk.ToString(), signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext);
            else if (cnf.TryGetValue(ConfirmationClaimTypes.Jwe, StringComparison.Ordinal, out var jwe))
                return await ResolvePopKeyFromJweAsync(jwe.ToString(), signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
            else if (cnf.TryGetValue(ConfirmationClaimTypes.Kid, StringComparison.Ordinal, out var kid))
                return await ResolvePopKeyFromKeyIdentifierAsync(kid.ToString(), signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
            else if (cnf.TryGetValue(ConfirmationClaimTypes.Jku, StringComparison.Ordinal, out var jku))
                return await ResolvePopKeyFromJkuAsync(jku.ToString(), signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
            else
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidCnfClaimException(LogHelper.FormatInvariant(LogMessages.IDX23014, cnf.ToString())));
        }

        /// <summary>
        /// Resolves a PoP <see cref="SecurityKey"/> from the asymmetric representation of a PoP key. 
        /// </summary>
        /// <param name="jwk">An asymmetric representation of a PoP key (JSON).</param>
        /// <param name="signedHttpRequest">A signed http request as a JWT.</param>
        /// <param name="validatedAccessToken">An access token ("at") that was already validated during the SignedHttpRequest validation process.</param>
        /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
        protected virtual SecurityKey ResolvePopKeyFromJwk(string jwk, JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext)
        {
            if (string.IsNullOrEmpty(jwk))
                throw LogHelper.LogArgumentNullException(nameof(jwk));

            var jsonWebKey = new JsonWebKey(jwk);

            if (JsonWebKeyConverter.TryConvertToSecurityKey(jsonWebKey, out var key))
            {
                if (key is AsymmetricSecurityKey)
                    return jsonWebKey;
                else
                    throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23015, key.GetType().ToString())));
            }
            else
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23016, jsonWebKey.ToString())));
        }

        /// <summary>
        /// Resolves a PoP <see cref="SecurityKey"/> from the encrypted symmetric representation of a PoP key. 
        /// </summary>
        /// <param name="jwe">An encrypted symmetric representation of a PoP key (JSON).</param>
        /// <param name="signedHttpRequest">A signed http request as a JWT.</param>
        /// <param name="validatedAccessToken">An access token ("at") that was already validated during the SignedHttpRequest validation process.</param> 
        /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
        protected virtual async Task<SecurityKey> ResolvePopKeyFromJweAsync(string jwe, JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(jwe))
                throw LogHelper.LogArgumentNullException(nameof(jwe));

            var jweJwt = _jwtTokenHandler.ReadJsonWebToken(jwe);

            IEnumerable<SecurityKey> decryptionKeys;
            if (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.CnfDecryptionKeysResolverAsync != null)
                decryptionKeys = await signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.CnfDecryptionKeysResolverAsync(jweJwt, cancellationToken).ConfigureAwait(false);
            else
                decryptionKeys = signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.CnfDecryptionKeys;

            if (decryptionKeys == null || !decryptionKeys.Any())
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23017)));

            var tokenDecryptionParameters = new TokenValidationParameters()
            {
                TokenDecryptionKeys = decryptionKeys,
                RequireSignedTokens = false,
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = false,
            };

            JsonWebKey jsonWebKey;
            try
            {
                var decryptedJson = _jwtTokenHandler.DecryptToken(jweJwt, tokenDecryptionParameters);
                jsonWebKey = new JsonWebKey(decryptedJson);
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23018, string.Join(", ", decryptionKeys.Select(x => x?.KeyId ?? "Null")), e), e));
            }

            if (JsonWebKeyConverter.TryConvertToSymmetricSecurityKey(jsonWebKey, out var symmetricKey))
                return jsonWebKey;
            else
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23019, jsonWebKey.GetType().ToString())));
        }

        /// <summary>
        /// Resolves a PoP <see cref="SecurityKey"/> from the URL reference to a PoP JWK set.
        /// The method throws an exception is there is more than one resolved PoP key.
        /// </summary>
        /// <param name="jku">A URL reference to a PoP JWK set.</param>
        /// <param name="signedHttpRequest">A signed http request as a JWT.</param>
        /// <param name="validatedAccessToken">An access token ("at") that was already validated during the SignedHttpRequest validation process.</param> 
        /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
        protected virtual async Task<SecurityKey> ResolvePopKeyFromJkuAsync(string jku, JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            return await GetPopKeyFromJkuAsync(jku, signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Resolves a PoP <see cref="SecurityKey"/> from the URL reference to a PoP key.  
        /// </summary>
        /// <param name="jku">A URL reference to a PoP JWK set.</param>
        /// <param name="kid">A PoP key identifier.</param>
        /// <param name="signedHttpRequest">A signed http request as a JWT.</param>
        /// <param name="validatedAccessToken">An access token ("at") that was already validated during the SignedHttpRequest validation process.</param> 
        /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
        protected virtual async Task<SecurityKey> ResolvePopKeyFromJkuAsync(string jku, string kid, JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(kid))
                throw LogHelper.LogArgumentNullException(nameof(kid));

            return  await GetPopKeyFromJkuAsync(jku, signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Gets a JWK set of PoP <see cref="SecurityKey"/> from the <paramref name="jku"/>.
        /// </summary>
        /// <param name="jku">A URL reference to a PoP JWK set.</param>
        /// <param name="signedHttpRequest">A signed http request as a JWT.</param>
        /// <param name="validatedAccessToken">An access token ("at") that was already validated during the SignedHttpRequest validation process.</param> 
        /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A collection of PoP <see cref="SecurityKey"/>.</returns>
        protected virtual async Task<SecurityKey> GetPopKeyFromJkuAsync(string jku, JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(jku))
                throw LogHelper.LogArgumentNullException(nameof(jku));

            if (!Utility.IsHttps(jku) && signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.RequireHttpsForJkuResourceRetrieval)
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23006, jku)));

            try
            {
                var httpClient = signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.HttpClientForJkuResourceRetrieval ?? _defaultHttpClient;
                var response = await httpClient.GetAsync(jku, cancellationToken).ConfigureAwait(false);
                return new JsonWebKey(await response.Content.ReadAsStringAsync().ConfigureAwait(false));
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23022, jku, e), e));
            }
        }

        /// <summary>
        /// Resolves a PoP <see cref="SecurityKey"/> using a key identifier of a PoP key. 
        /// </summary>
        /// <param name="kid">A <see cref="ConfirmationClaimTypes.Kid"/> claim value.</param>
        /// <param name="signedHttpRequest">A signed http request as a JWT.</param>
        /// <param name="validatedAccessToken">An access token ("at") that was already validated during the SignedHttpRequest validation process.</param>
        /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
        /// <remarks>
        /// To resolve a PoP <see cref="SecurityKey"/> using only the 'kid' claim, set the <see cref="SignedHttpRequestValidationParameters.PopKeyResolverAsync"/> delegate.
        /// </remarks>
        protected virtual async Task<SecurityKey> ResolvePopKeyFromKeyIdentifierAsync(string kid, JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.PopKeyResolverAsync != null)
                return await signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.PopKeyResolverAsync(signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
            else if (signedHttpRequest is JsonWebToken jwtSignedHttpRequest && jwtSignedHttpRequest.TryGetPayloadValue(ConfirmationClaimTypes.Cnf, out JObject signedHttpRequestCnf) && signedHttpRequestCnf != null)
                return await ResolvePopKeyFromCnfReferenceAsync(kid, signedHttpRequestCnf.ToString(Formatting.None), signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
            else
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23023)));
        }

        /// <summary>
        /// Resolves a PoP key from a "cnf" reference and validates the reference.
        /// </summary>
        /// <param name="cnfReferenceId">A reference to the root "cnf" claim, as base64url-encoded JWK thumbprint.</param>
        /// <param name="confirmationClaim">A confirmation ("cnf") claim as a string.</param>
        /// <param name="signedHttpRequest">A signed http request as a JWT.</param>
        /// <param name="validatedAccessToken">An access token ("at") that was already validated during the SignedHttpRequest validation process.</param>
        /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
        /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
        /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
        /// <remarks><paramref name="cnfReferenceId"/> MUST match the base64url-encoded thumbprint of a JWK resolved from the <paramref name="confirmationClaim"/>.</remarks>
        protected virtual async Task<SecurityKey> ResolvePopKeyFromCnfReferenceAsync(string cnfReferenceId, string confirmationClaim, JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            // resolve PoP key from the confirmation claim, but set signedHttpRequest to null to prevent recursion.
            var popKey = await ResolvePopKeyFromCnfClaimAsync(confirmationClaim, null, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);

            JsonWebKey jwtPopKey;
            if (popKey is JsonWebKey)
                jwtPopKey = (JsonWebKey)popKey;
            else
                jwtPopKey = JsonWebKeyConverter.ConvertFromSecurityKey(popKey);

            var jwkPopKeyThumprint = Base64UrlEncoder.Encode(jwtPopKey.ComputeJwkThumbprint());

            // validate reference
            if (!string.Equals(cnfReferenceId, jwkPopKeyThumprint, StringComparison.Ordinal))
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23034, cnfReferenceId, jwkPopKeyThumprint, confirmationClaim)));

            return jwtPopKey;
        }
        #endregion

        #region Private utility methods
        private string CalculateBase64UrlEncodedHash(string data)
        {
            return CalculateBase64UrlEncodedHash(Encoding.UTF8.GetBytes(data));
        }

        private string CalculateBase64UrlEncodedHash(byte[] bytes)
        {
            using (var hash = SHA256.Create())
            {
                var hashedBytes = hash.ComputeHash(bytes);
                return Base64UrlEncoder.Encode(hashedBytes);
            }
        }

        /// <summary>
        /// Ensures that the <paramref name="uri"/> is <see cref="UriKind.Absolute"/>.
        /// If <paramref name="uri"/> is <see cref="UriKind.Absolute"/>, the method returns it as-is.
        /// If <paramref name="uri"/> is <see cref="UriKind.Relative"/>, new helper <see cref="UriKind.Absolute"/> URI is created and returned.
        /// Throws in case that an <see cref="UriKind.Absolute"/> URI can't be created.
        /// </summary>
        private Uri EnsureAbsoluteUri(Uri uri)
        {
            if (uri.IsAbsoluteUri)
            {
                return uri;
            }
            else
            {
                if (!Uri.TryCreate(_baseUriHelper, uri, out Uri absoluteUri))
                    throw LogHelper.LogExceptionMessage(new SignedHttpRequestCreationException(LogHelper.FormatInvariant(LogMessages.IDX23007, uri.ToString())));

                return absoluteUri;
            }
        }

        /// <summary>
        /// Sanitizes the query params to comply with the specification.
        /// </summary>
        /// <remarks>https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-7.5.</remarks>
        private Dictionary<string, string> SanitizeQueryParams(Uri httpRequestUri)
        {
            // Remove repeated query params according to the spec: https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-7.5.
            // "If a header or query parameter is repeated on either the outgoing request from the client or the
            // incoming request to the protected resource, that query parameter or header name MUST NOT be covered by the hash and signature."
            var sanitizedQueryParams = new Dictionary<string, string>(StringComparer.Ordinal);
            var repeatedQueryParams = new List<string>();

            var queryString = httpRequestUri.Query.TrimStart('?');
            if (string.IsNullOrEmpty(queryString))
                return sanitizedQueryParams;

            var queryParamKeyValuePairs = queryString.Split('&');
            foreach (var queryParamValuePair in queryParamKeyValuePairs)
            {
                var queryParamKeyValuePairArray = queryParamValuePair.Split('=');
                if (queryParamKeyValuePairArray.Count() == 2)
                {
                    var queryParamName = queryParamKeyValuePairArray[0];
                    var queryParamValue = queryParamKeyValuePairArray[1];
                    if (!string.IsNullOrEmpty(queryParamName))
                    {
                        // if sanitizedQueryParams already contains the query parameter name it means that the queryParamName is repeated.
                        // in that case queryParamName should not be added, and the existing entry in sanitizedQueryParams should be removed.
                        if (sanitizedQueryParams.ContainsKey(queryParamName))
                            repeatedQueryParams.Add(queryParamName);
                        else if (!string.IsNullOrEmpty(queryParamValue))
                            sanitizedQueryParams.Add(queryParamName, queryParamValue);
                    }
                }
            }

            if (repeatedQueryParams.Any())
            {
                LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX23004, string.Join(", ", repeatedQueryParams)));

                foreach (var repeatedQueryParam in repeatedQueryParams)
                {
                    if (sanitizedQueryParams.ContainsKey(repeatedQueryParam))
                        sanitizedQueryParams.Remove(repeatedQueryParam);
                }
            }

            return sanitizedQueryParams;
        }

        /// <summary>
        /// Sanitizes the headers to comply with the specification.
        /// </summary>
        /// <remarks>
        /// https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-4.1
        /// https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-7.5
        /// </remarks>
        private Dictionary<string, string> SanitizeHeaders(IDictionary<string, IEnumerable<string>> headers)
        {
            // Remove repeated headers according to the spec: https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-7.5.
            // "If a header or query parameter is repeated on either the outgoing request from the client or the
            // incoming request to the protected resource, that query parameter or header name MUST NOT be covered by the hash and signature."
            var sanitizedHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var repeatedHeaders = new List<string>();
            foreach (var header in headers)
            {
                var headerName = header.Key;

                if (string.IsNullOrEmpty(headerName))
                    continue;

                // Don't include the authorization header (https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-4.1).
                if (string.Equals(headerName, SignedHttpRequestConstants.AuthorizationHeader, StringComparison.OrdinalIgnoreCase))
                    continue;

                // if sanitizedHeaders already contains the header name it means that the headerName is repeated.
                // in that case headerName should not be added, and the existing entry in sanitizedHeaders should be removed.
                if (sanitizedHeaders.ContainsKey(headerName))
                {
                    repeatedHeaders.Add(headerName.ToLower());
                }
                // if header has more than one value don't add it to the sanitizedHeaders as it's repeated.
                else if (header.Value.Count() > 1)
                {
                    repeatedHeaders.Add(headerName.ToLower());
                }
                else if (header.Value.Count() == 1 && !string.IsNullOrEmpty(header.Value.First()))
                    sanitizedHeaders.Add(headerName, header.Value.First());
            }

            if (repeatedHeaders.Any())
            {
                LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX23005, string.Join(", ", repeatedHeaders)));

                foreach (var repeatedHeaderName in repeatedHeaders)
                {
                    if (sanitizedHeaders.ContainsKey(repeatedHeaderName))
                        sanitizedHeaders.Remove(repeatedHeaderName);
                }
            }

            return sanitizedHeaders;
        }
        #endregion
    }
}
