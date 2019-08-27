//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

#pragma warning disable 1591

using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Wcf
{

    public class WsFederationHttpBinding : WSHttpBindingBase
    {
        static readonly MessageSecurityVersion WSMessageSecurityVersion = MessageSecurityVersion.WSSecurity11WSTrustFebruary2005WSSecureConversationFebruary2005WSSecurityPolicy11BasicSecurityProfile10;

        WsFederationHttpSecurity security = new WsFederationHttpSecurity();

        public WsFederationHttpBinding(string configName)
            : this()
        {
            ApplyConfiguration(configName);
        }

        public WsFederationHttpBinding()
            : base()
        {
        }

        public WsFederationHttpBinding(WsFederationHttpSecurityMode securityMode)
            : this(securityMode, false)
        {
        }

        public WsFederationHttpBinding(WsFederationHttpSecurityMode securityMode, bool reliableSessionEnabled)
            : base(reliableSessionEnabled)
        {
            security.Mode = securityMode;
        }


        internal WsFederationHttpBinding(WsFederationHttpSecurity security)
        {
            this.security = security;
        }

        public WsFederationHttpSecurity Security
        {
            get { return this.security; }
            set
            {
                if (value == null)
                    throw LogHelper.LogArgumentNullException("value");

                this.security = value;
            }
        }

        //void ApplyConfiguration(string configurationName)
        //{
        //    WsFederationHttpBindingCollectionElement section = WsFederationHttpBindingCollectionElement.GetBindingCollectionElement();
        //    WsFederationHttpBindingElement element = section.Bindings[configurationName];
        //    if (element == null)
        //    {
        //        throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new ConfigurationErrorsException(
        //            SR.GetString(SR.ConfigInvalidBindingConfigurationName,
        //                         configurationName,
        //                         ConfigurationStrings.WsFederationHttpBindingCollectionElementName)));
        //    }
        //    else
        //    {
        //        element.ApplyConfiguration(this);
        //    }
        //}


        // if you make changes here, see also WS2007FederationHttpBinding.TryCreate()
        internal static bool TryCreate(SecurityBindingElement sbe, TransportBindingElement transport, out Binding binding)
        {
            binding = null;

            // reverse GetTransport
            HttpTransportSecurity transportSecurity = new HttpTransportSecurity();
            WsFederationHttpSecurityMode mode;
            if (!GetSecurityModeFromTransport(transport, transportSecurity, out mode))
            {
                return false;
            }

            HttpsTransportBindingElement httpsBinding = transport as HttpsTransportBindingElement;
            if (httpsBinding != null && httpsBinding.MessageSecurityVersion != null)
            {
                if (httpsBinding.MessageSecurityVersion.SecurityPolicyVersion != WSMessageSecurityVersion.SecurityPolicyVersion)
                {
                    return false;
                }
            }

            WsFederationHttpSecurity security;
            if (TryCreateSecurity(sbe, mode, transportSecurity, out security))
            {
                binding = new WsFederationHttpBinding(security);
            }

            return binding != null;
        }

        protected override TransportBindingElement GetTransport()
        {
            if (security.Mode == WsFederationHttpSecurityMode.None)
            {
                return this.HttpTransport;
            }
            else
            {
                return this.HttpsTransport;
            }
        }

        internal static bool GetSecurityModeFromTransport(TransportBindingElement transport, HttpTransportSecurity transportSecurity, out WsFederationHttpSecurityMode mode)
        {
            mode = WsFederationHttpSecurityMode.None | WsFederationHttpSecurityMode.Message | WsFederationHttpSecurityMode.TransportWithMessageCredential;
            if (transport is HttpsTransportBindingElement)
            {
                mode = WsFederationHttpSecurityMode.TransportWithMessageCredential;
            }
            else if (transport is HttpTransportBindingElement)
            {
                mode = WsFederationHttpSecurityMode.None | WsFederationHttpSecurityMode.Message;
            }
            else
            {
                return false;
            }
            return true;
        }

        // if you make changes here, see also WS2007FederationHttpBinding.TryCreateSecurity()
        static bool TryCreateSecurity(SecurityBindingElement sbe, WsFederationHttpSecurityMode mode, HttpTransportSecurity transportSecurity, out WsFederationHttpSecurity security)
        {
            if (!WsFederationHttpSecurity.TryCreate(sbe, mode, transportSecurity, WsMessageSecurityVersion, out security))
                return false;

            // the last check: make sure that security binding element match the incoming security
            return SecurityElement.AreBindingsMatching(security.CreateMessageSecurity(isReliableSession, WSMessageSecurityVersion), sbe);
        }

        public override BindingElementCollection CreateBindingElements()
        {   // return collection of BindingElements

            BindingElementCollection bindingElements = base.CreateBindingElements();
            // order of BindingElements is important

            return bindingElements;
        }
    }
}
