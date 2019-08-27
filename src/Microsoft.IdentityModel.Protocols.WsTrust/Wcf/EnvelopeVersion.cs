//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

#pragma warning disable 1591

using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Wcf
{
    public sealed class EnvelopeVersion
    {
        private static string Soap11ToStringFormat = "Soap11({ 0})";
        private static string Soap12ToStringFormat = "Soap12({ 0})";
        private static string EnvelopeNoneToStringFormat = "EnvelopeNone({ 0})";
        private static string Role = "role";
        private static string EnvelopeNone = "http://schemas.microsoft.com/ws/2005/05/envelope/none";

        static EnvelopeVersion soap11 =
            new EnvelopeVersion(
                "",
                "http://schemas.xmlsoap.org/soap/actor/next",
                SoapConstants.Namespace11,
                SoapConstants.Actor,
                Soap11ToStringFormat,
                "Client",
                "Server");

        static EnvelopeVersion soap12 =
            new EnvelopeVersion(
                "http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver",
                "http://www.w3.org/2003/05/soap-envelope/role/next",
                SoapConstants.Namespace12,
                Role,
                Soap12ToStringFormat,
                "Sender",
                "Receiver");

        static EnvelopeVersion none = new EnvelopeVersion(
                null,
                null,
                EnvelopeNone,
                null,
                EnvelopeNoneToStringFormat,
                "Sender",
                "Receiver");

        EnvelopeVersion(
            string ultimateReceiverActor, 
            string nextDestinationActorValue,
            string ns, 
            string actor, 
            string toStringFormat, 
            string senderFaultName, 
            string receiverFaultName)
        {
            ToStringFormat = toStringFormat;
            UltimateDestinationActor = ultimateReceiverActor;
            NextDestinationActorValue = nextDestinationActorValue;
            Namespace = ns;
            Actor = actor;
            SenderFaultName = senderFaultName;
            ReceiverFaultName = receiverFaultName;

            if (ultimateReceiverActor != null)
            {
                if (ultimateReceiverActor.Length == 0)
                {
                    MustUnderstandActorValues = new string[] { "", nextDestinationActorValue };
                    UltimateDestinationActorValues = new string[] { "", nextDestinationActorValue };
                }
                else
                {
                    MustUnderstandActorValues = new string[] { "", ultimateReceiverActor, nextDestinationActorValue };
                    UltimateDestinationActorValues = new string[] { "", ultimateReceiverActor, nextDestinationActorValue };
                }
            }
        }

        internal string Actor
        {
            get;
        }

        internal string Namespace
        {
            get;
        }

        public string NextDestinationActorValue
        {
            get;
        }

        public static EnvelopeVersion None
        {
            get;
        }

        public static EnvelopeVersion Soap11
        {
            get;
        }

        public static EnvelopeVersion Soap12
        {
            get;
        }

        internal string ReceiverFaultName
        {
            get;
        }

        internal string SenderFaultName
        {
            get;
        }

        internal string[] MustUnderstandActorValues
        {
            get;
        }

        internal string UltimateDestinationActor
        {
            get;
        }

        public string[] GetUltimateDestinationActorValues()
        {
            return (string[])UltimateDestinationActorValues;
        }

        internal string[] UltimateDestinationActorValues
        {
            get;
        }

        internal bool IsUltimateDestinationActor(string actor)
        {
            return actor.Length == 0 || actor == UltimateDestinationActor || actor == NextDestinationActorValue;
        }

        public override string ToString()
        {
            return LogHelper.FormatInvariant(ToStringFormat, Namespace);
        }

        public string ToStringFormat { get; }
    }
}
