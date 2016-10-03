using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ApplePayDecrypter.Definition
{
    [Serializable]
    public class ApplePayRequest
    {
        private string version;

        public string Version
        {
            get { return version; }
            set { version = value; }
        }

        private string data;

        public string Data
        {
            get { return data; }
            set { data = value; }
        }
        private string signature;

        public string Signature
        {
            get { return signature; }
            set { signature = value; }
        }

        private ApplePayHeader applePayHeader;

        public ApplePayHeader ApplePayHeader
        {
            get { return applePayHeader; }
            set { applePayHeader = value; }
        }


        public string CertFilePath
        {
            get { return ConfigurationManager.AppSettings["ApplePayCertPath"]; }
        }

        public string P12Path
        {
            get { return ConfigurationManager.AppSettings["ApplePayP12Path"]; }
        }

        public string P12FilePassword
        {
            get { return ConfigurationManager.AppSettings["ApplePayP12FilePassword"]; }
        }

        public string MerchantIdentifier
        {
            get { return ConfigurationManager.AppSettings["AppleMerchantIdentifier"]; }
        }

        public byte[] PrivateKeyBytes
        {
            get;
            set;
        }




    }
}
