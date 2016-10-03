package com.apple.merchant;

import com.apple.merchant.provider.ColorSystemPrint;
import com.apple.merchant.provider.CommandLineEncryptedDataProvider;
import com.apple.merchant.provider.EncryptedDataProvider;
import com.apple.merchant.provider.StaticEncryptedDataProvider;
import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Hello world!
 */
public class PaymentDecryptHelper {
    private static final Charset UTF_8                = Charset.forName( "UTF-8" );
    private static final byte[]  COUNTER              = {0x00, 0x00, 0x00, 0x01};
    private static final byte[]  APPLE_OEM            = "Apple".getBytes( UTF_8 );
    private static final byte[]  ALG_IDENTIFIER_BYTES = "id-aes256-GCM".getBytes( UTF_8 );

    static {
        Security.addProvider( new BouncyCastleProvider() );
    }

    private EncryptedDataProvider _dataProvider;
    private X509Certificate       _certificate;

    public static void main( String[] args ) throws Exception {
        PaymentDecryptHelper paymentDecryptHelper = new PaymentDecryptHelper();
        paymentDecryptHelper.performDecryptOperation();
    }

    private void performDecryptOperation() throws Exception {
        _dataProvider = determineDataProvider();

        PrivateKey privateKey = inflatePrivateKey();

        _certificate = (X509Certificate) inflateCertificate();

        AsymmetricKeyVerifier verifier = new AsymmetricKeyVerifier(privateKey, _certificate.getPublicKey() );

        if ( !verifier.verify() ) {
            throw new Exception( "Asymmetric keys do not match!" );
        }

        byte[] rawData       = decrypt( privateKey, _dataProvider.getEphemeralKey(), _dataProvider.getData() );
        String plainTextData = new String( rawData, UTF_8 );

        ColorSystemPrint.println( "Decrypted data:" );
        ColorSystemPrint.println( plainTextData );
    }

    private byte[] decrypt( PrivateKey merchantPrivateKey, byte[] ephemeralPublicKeyBytes, byte[] data ) throws Exception {
        // Reconstitute Ephemeral Public Key
        KeyFactory         keyFactory         = KeyFactory.getInstance( "ECDH", "BC" );
        X509EncodedKeySpec encodedKeySpec     = new X509EncodedKeySpec( ephemeralPublicKeyBytes );
        ECPublicKey        ephemeralPublicKey = (ECPublicKey) keyFactory.generatePublic( encodedKeySpec );

        // Perform KeyAgreement
        KeyAgreement agreement = KeyAgreement.getInstance( "ECDH", "BC" );
        agreement.init( merchantPrivateKey );
        agreement.doPhase( ephemeralPublicKey, true );
        byte[] sharedSecret = agreement.generateSecret();

        // Perform KDF
        byte[] derivedSecret = performKeyDerivationFunction( sharedSecret );

        // Use the derived secret to decrypt the data
        SecretKeySpec   key       = new SecretKeySpec( derivedSecret, "AES" );
        byte[]          ivBytes   = new byte[16];
        IvParameterSpec ivSpec    = new IvParameterSpec( ivBytes );
        Cipher          aesCipher = Cipher.getInstance( "AES/GCM/NoPadding", "BC" );
        aesCipher.init( Cipher.DECRYPT_MODE, key, ivSpec );

        return aesCipher.doFinal( data );
    }

    private byte[] performKeyDerivationFunction( byte[] sharedSecret ) throws Exception {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        // Add counter
        byteArrayOutputStream.write( COUNTER );

        // Add shared secret
        byteArrayOutputStream.write( sharedSecret );

        // Add algorithm identifier len
        byteArrayOutputStream.write( ALG_IDENTIFIER_BYTES.length );

        // Add algorithm identifier
        byteArrayOutputStream.write( ALG_IDENTIFIER_BYTES );

        // Add Wallet Provider
        byteArrayOutputStream.write( APPLE_OEM );

        // Add Merchant Id
        byteArrayOutputStream.write( HexBin.decode( new String( _certificate.getExtensionValue( "1.2.840.113635.100.6.32" ), UTF_8 ).substring( 4 ) ) );

        // Perform KDF
        MessageDigest messageDigest = MessageDigest.getInstance( "SHA256", "BC" );

        return messageDigest.digest( byteArrayOutputStream.toByteArray() );
    }

    private Certificate inflateCertificate() throws Exception {
        InputStream        stream             = new ByteArrayInputStream( _dataProvider.getPublicCertificate() );
        CertificateFactory certificateFactory = CertificateFactory.getInstance( "X.509" );
        Certificate        certificate        = certificateFactory.generateCertificate( stream );
        stream.close();
        return certificate;
    }

    private PrivateKey inflatePrivateKey() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance( "EC" );
        return keyFactory.generatePrivate( new PKCS8EncodedKeySpec( _dataProvider.getPrivateKeyBytes() ) );
    }

    private EncryptedDataProvider determineDataProvider() {
        if ( CommandLineEncryptedDataProvider.hasArguments() ) {
            ColorSystemPrint.println( "Found required properties, using data from the command line" );
            return new CommandLineEncryptedDataProvider();
        } else {
            ColorSystemPrint.println( "Did not find a subset of the following properties, following back onto static data: " + Arrays.toString( CommandLineEncryptedDataProvider.REQUIRED_ARGUMENTS ) );
            return new StaticEncryptedDataProvider();
        }
    }
}
