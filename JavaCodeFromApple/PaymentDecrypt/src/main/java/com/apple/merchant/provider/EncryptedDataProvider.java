package com.apple.merchant.provider;

/**
 * Created by matthewbyington on 8/8/16.
 */
public interface EncryptedDataProvider {
    byte[] getData();

    byte[] getEphemeralKey();

    byte[] getPrivateKeyBytes();

    byte[] getPublicCertificate();
}
