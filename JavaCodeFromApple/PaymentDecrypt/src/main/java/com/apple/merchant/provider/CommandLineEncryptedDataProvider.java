package com.apple.merchant.provider;

import org.bouncycastle.util.encoders.Base64;

import java.util.Properties;

/**
 * Created by matthewbyington on 8/8/16.
 */
public class CommandLineEncryptedDataProvider implements EncryptedDataProvider {
    public static final String[] REQUIRED_ARGUMENTS = {"data", "ephemeralPublicKey", "privateKey", "publicCertificate"};

    public byte[] getData() {
        return getArgument( REQUIRED_ARGUMENTS[0] );
    }

    public byte[] getEphemeralKey() {
        return getArgument( REQUIRED_ARGUMENTS[1] );
    }

    public byte[] getPrivateKeyBytes() {
        return getArgument( REQUIRED_ARGUMENTS[2] );
    }

    public byte[] getPublicCertificate() {
        return getArgument( REQUIRED_ARGUMENTS[3] );
    }

    private byte[] getArgument( String name ) {
        String value = System.getProperty( name );

        if ( null == value ) {
            System.err.println( "Missing System Property: " + name );
            System.exit( 1 );
        }

        return Base64.decode( value );
    }

    public static boolean hasArguments() {
        Properties properties = System.getProperties();

        for ( String propertyName : REQUIRED_ARGUMENTS ) {
            if ( !properties.containsKey( propertyName ) ) {
                return false;
            }
        }

        return true;
    }
}
