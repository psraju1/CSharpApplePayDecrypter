using Microsoft.VisualStudio.TestTools.UnitTesting;
using ApplePayDecrypter;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ApplePayDecrypter.Definition;
using Org.BouncyCastle.Utilities.Encoders;
using Xunit;

namespace ApplePayDecrypter.Tests
{
    [TestClass]
    public class ApplePayTests
    {
       

        [TestMethod]
        public void Decrypt__ShouldDecryptMessage__WhenPassAllRequiredDocuments()
        {
            ApplePayRequest applePayRequest = new ApplePayRequest();
            applePayRequest.ApplePayHeader = new ApplePayHeader();
            applePayRequest.ApplePayHeader.EphemeralPublicKey =
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEl/XAbOgrSCupps/QbIxJ3u4QZ1PlbO5uGDD1zj/JGMoephYSEgw+63gHQHekx3T8duXN3CoYafUpuQlwOeK6/w==";
            applePayRequest.PrivateKeyBytes =
                Base64.Decode(
                    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjyo3fzxT7j+CFxC7I4B5iVee2FUyn2vfOSjcgp2/g6qhRANCAARdoBFEtnuapXFKw4DYWsW0yV4bavpdWKszkefi19AhlIRE3WSNWSn25W5tZNFjMWtLISBmqANyufx2xP19oRvy");
            applePayRequest.Data =
                "0cWHZj3Py20Nxh8VrANfcXSFFaaNCJM9HpCPiUhb63GWi7+Aya0BmsKfELoK/Pp+1hvmJzO0DtkdYrtLQRnKRKUMX+KfEsQO3eKLEOaRm12qf1jgXG7HUE1r+BlrK9BC24QzyZkqYVbdTSbE8CTmDuiDSVjQi0fBwxo+MdjsWg+ap6RDlmSXVKXuGS1to5Ae/VDnwBBMuDNYJiJYSR9LWU7eO6HL6ke6+xjXcRhfxexeZ1y9XToTcDrC0M7xM3kAHkTyDV30m63MKdb7cpSV/7DVgj99AX9XrLlVJndAnBLI7jMsOFCTho86U0fJJ40XDklR8X5x43NKL+c2SimUNBMZkiZLygQSUrFD41cKb/7UIyB9c7Sk9UJmTM24FOeVt/RH2cIX+okRB6UzewVGZEFvV/PWbJqaOCWxISMjJc8HAkWa0Q1ARVKTzCS6ZgsPFZcao0Z3/j46kCxN/RYeYG7hfgrtaH8hqnvicac3khhFAU9RbjMZCmGdVzyuaxz/4SKGtDgN22y8sPsiWORi6NM+1As5nHWMgP7dO2ouI3wcuaxHADHfGm5aNQ==";

            ApplePay applePay = new ApplePay(applePayRequest);
            applePay.Decrypt();
        }
    }
}