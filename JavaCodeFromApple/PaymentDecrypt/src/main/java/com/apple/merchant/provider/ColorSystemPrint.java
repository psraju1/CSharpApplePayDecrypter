package com.apple.merchant.provider;

/**
 * Created by matthewbyington on 8/8/16.
 */
public class ColorSystemPrint {
    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_BLUE  = "\u001B[34m";

    public static void println( String text ) {
        System.out.println( ANSI_BLUE + text + ANSI_RESET );
    }
}
