//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

#pragma warning disable 1591

using System;
using System.Xml;
using Microsoft.IdentityModel.WsAddressing;

namespace Microsoft.IdentityModel.Wcf
{
    public sealed class AddressingVersion
    {
        string ns;
        string toStringFormat;
        string anonymous;
        Uri anonymousUri;
        Uri noneUri;
        string faultAction;
        string defaultFaultAction;
        MessagePartSpecification signedMessageParts;

        static AddressingVersion none = new AddressingVersion(WsAddressingConstants.AddressingNone,  null, null, null, null);

        static AddressingVersion addressing10 = new AddressingVersion(WsAddressing10Constants.Namespace, WsAddressingConstants.Anonymous, WsAddressingConstants.NoneAddress,
            WsAddressingConstants.FaultAction, WsAddressingConstants.DefaultFaultAction);
        static MessagePartSpecification addressing10SignedMessageParts;

        static AddressingVersion addressing200408 = new AddressingVersion(Addressing200408Strings.Namespace,
            XD.Addressing200408Dictionary.Namespace, SR.Addressing200408ToStringFormat, Addressing200408SignedMessageParts,
            Addressing200408Strings.Anonymous, XD.Addressing200408Dictionary.Anonymous, null,
            Addressing200408Strings.FaultAction, Addressing200408Strings.DefaultFaultAction);
        static MessagePartSpecification addressing200408SignedMessageParts;

        AddressingVersion(string ns, string anonymous, string none, string faultAction, string defaultFaultAction)
        {
            this.ns = ns;
            this.toStringFormat = toStringFormat;
            this.anonymous = anonymous;

            if (anonymous != null)
            {
                this.anonymousUri = new Uri(anonymous);
            }

            if (none != null)
            {
                this.noneUri = new Uri(none);
            }

            this.faultAction = faultAction;
            this.defaultFaultAction = defaultFaultAction;
        }

        public static AddressingVersion WSAddressingAugust2004
        {
            get { return addressing200408; }
        }

        public static AddressingVersion WSAddressing10
        {
            get { return addressing10; }
        }

        public static AddressingVersion None
        {
            get { return none; }
        }

        internal string Namespace
        {
            get { return ns; }
        }

        static MessagePartSpecification Addressing10SignedMessageParts
        {
            get
            {
                if (addressing10SignedMessageParts == null)
                {
                    MessagePartSpecification s = new MessagePartSpecification(
                        new XmlQualifiedName(WsAddressingConstants.Elements.To, WsAddressing10Constants.Namespace),
                        new XmlQualifiedName(WsAddressingConstants.Elements.From, WsAddressing10Constants.Namespace),
                        new XmlQualifiedName(WsAddressingConstants.Elements.FaultTo, WsAddressing10Constants.Namespace),
                        new XmlQualifiedName(WsAddressingConstants.Elements.ReplyTo, WsAddressing10Constants.Namespace),
                        new XmlQualifiedName(WsAddressingConstants.Elements.MessageId, WsAddressing10Constants.Namespace),
                        new XmlQualifiedName(WsAddressingConstants.Elements.RelatesTo, WsAddressing10Constants.Namespace),
                        new XmlQualifiedName(WsAddressingConstants.Elements.Action, WsAddressing10Constants.Namespace)
                        );
                    s.MakeReadOnly();
                    addressing10SignedMessageParts = s;
                }

                return addressing10SignedMessageParts;
            }
        }

        static MessagePartSpecification Addressing200408SignedMessageParts
        {
            get
            {
                if (addressing200408SignedMessageParts == null)
                {
                    MessagePartSpecification s = new MessagePartSpecification(
                        new XmlQualifiedName(WsAddressingConstants.Elements.To, WsAddressing200408Constants.Namespace),
                        new XmlQualifiedName(WsAddressingConstants.Elements.From, WsAddressing200408Constants.Namespace),
                        new XmlQualifiedName(WsAddressingConstants.Elements.FaultTo, WsAddressing200408Constants.Namespace),
                        new XmlQualifiedName(WsAddressingConstants.Elements.ReplyTo, WsAddressing200408Constants.Namespace),
                        new XmlQualifiedName(WsAddressingConstants.Elements.MessageId, WsAddressing200408Constants.Namespace),
                        new XmlQualifiedName(WsAddressingConstants.Elements.RelatesTo, WsAddressing200408Constants.Namespace),
                        new XmlQualifiedName(WsAddressingConstants.Elements.Action, WsAddressing200408Constants.Namespace)
                        );
                    s.MakeReadOnly();
                    addressing200408SignedMessageParts = s;
                }

                return addressing200408SignedMessageParts;
            }
        }

        internal string Anonymous
        {
            get { return anonymous; }
        }

        internal Uri AnonymousUri
        {
            get { return anonymousUri; }
        }

        internal Uri NoneUri
        {
            get { return noneUri; }
        }

        internal string FaultAction   // the action for addressing faults
        {
            get { return faultAction; }
        }

        internal string DefaultFaultAction  // a default string that can be used for non-addressing faults
        {
            get { return defaultFaultAction; }
        }

        internal MessagePartSpecification SignedMessageParts
        {
            get
            {
                return this.signedMessageParts;
            }
        }

        public override string ToString()
        {
            return SR.GetString(toStringFormat, Namespace);
        }
    }
}
