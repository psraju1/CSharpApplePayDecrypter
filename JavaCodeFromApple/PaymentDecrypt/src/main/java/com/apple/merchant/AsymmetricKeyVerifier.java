package com.apple.merchant;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.UUID;

/**
 * Created by matthewbyington on 8/8/16.
 */
public class AsymmetricKeyVerifier {
    private static final String SIGNATURE_ALGORITHM_NAME = "SHA256withECDSA";

    private final PrivateKey _privateKey;
    private final PublicKey  _publicKey;

    AsymmetricKeyVerifier( PrivateKey privateKey, PublicKey publicKey ) {
        _privateKey = privateKey;
        _publicKey = publicKey;
    }

    boolean verify() throws Exception {
        byte[] data             = UUID.randomUUID().toString().getBytes();
        byte[] digitalSignature = signData( data );
        return verifySig( data, digitalSignature );
    }

    private byte[] signData( byte[] data ) throws Exception {
        Signature signer = Signature.getInstance( SIGNATURE_ALGORITHM_NAME );
        signer.initSign( _privateKey );
        signer.update( data );
        return signer.sign();
    }

    private boolean verifySig( byte[] data, byte[] sig ) throws Exception {
        Signature signer = Signature.getInstance( SIGNATURE_ALGORITHM_NAME );
        signer.initVerify( _publicKey );
        signer.update( data );
        return signer.verify( sig );
    }
}
