using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ApplePayDecrypter.Definition
{
    [Serializable]
    public class ApplePayHeader
    {
        private string ephemeralPublicKey;

        public string EphemeralPublicKey
        {
            get { return ephemeralPublicKey; }
            set { ephemeralPublicKey = value; }
        }

        private string publicKeyHash;

        public string PublicKeyHash
        {
            get { return publicKeyHash; }
            set { publicKeyHash = value; }
        }

        private string transactionId;

        public string TransactionId
        {
            get { return transactionId; }
            set { transactionId = value; }
        }
    }
}
