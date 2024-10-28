package ch.epfl.cs107.crypto;

import ch.epfl.cs107.Helper;

import static ch.epfl.cs107.utils.Text.*;
import static ch.epfl.cs107.utils.Image.*;
import static ch.epfl.cs107.utils.Bit.*;
import static ch.epfl.cs107.stegano.ImageSteganography.*;
import static ch.epfl.cs107.stegano.TextSteganography.*;
import static ch.epfl.cs107.crypto.Encrypt.*;
import static ch.epfl.cs107.crypto.Decrypt.*;
import static ch.epfl.cs107.Main.*;

/**
 * <b>Task 2: </b>Utility class to encrypt a given plain text.
 *
 * @author Hamza REMMAL (hamza.remmal@epfl.ch)
 * @version 1.0.0
 * @since 1.0.0
 */
public final class Encrypt {

    // DO NOT CHANGE THIS, MORE ON THAT ON WEEK 7
    private Encrypt(){}

    // ============================================================================================
    // ================================== CAESAR'S ENCRYPTION =====================================
    // ============================================================================================

    /**
     * Method to encode a byte array message using a single character key
     * the key is simply added to each byte of the original message
     *
     * @param plainText The byte array representing the string to encode
     * @param key the byte corresponding to the char we use to shift
     * @return an encoded byte array
     */
    public static byte[] caesar(byte[] plainText, byte key) {
        final int alphaSize = 256;
        byte[] ans = new byte[plainText.length];
        for(int i = 0; i<ans.length;i++){
            ans[i] = (byte)((plainText[i] + key)%alphaSize);
        }
        return ans;
    }

    // ============================================================================================
    // =============================== VIGENERE'S ENCRYPTION ======================================
    // ============================================================================================

    /**
     * Method to encode a byte array using a byte array keyword
     * The keyword is repeated along the message to encode
     * The bytes of the keyword are added to those of the message to encode
     * @param plainText the byte array representing the message to encode
     * @param keyword the byte array representing the key used to perform the shift
     * @return an encoded byte array
     */
    public static byte[] vigenere(byte[] plainText, byte[] keyword) {
        final int alphaSize = 256;
        byte[] ans = new byte[plainText.length];
        for(int i = 0; i<ans.length;i++){
            ans[i] = (byte)((plainText[i] + keyword[i% keyword.length])%alphaSize);
        }
        return ans;
    }

    // ============================================================================================
    // =================================== CBC'S ENCRYPTION =======================================
    // ============================================================================================

    /**
     * Method applying a basic chain block counter of XOR without encryption method.
     * @param plainText the byte array representing the string to encode
     * @param iv the pad of size BLOCKSIZE we use to start the chain encoding
     * @return an encoded byte array
     */
    public static byte[] cbc(byte[] plainText, byte[] iv) {
        byte[] ans = new byte[plainText.length];
        final int length = iv.length;
        int counter = plainText.length/length;
        int counter2 = plainText.length%length;
        int step = 1;
        for(int i = 0; i < length; i++){
            ans[i] = (byte)(plainText[i]^iv[i]);
        }
        while(step!=counter){
            for(int i = length*step; i < length*(step+1);i++){
                ans[i] = (byte)(plainText[i]^ans[i-length]);
            }
            step++;
        }
        if(counter2 != 0){
            for(int i = length*step; i < (length*step)+counter2;i++){
                ans[i] = (byte)(plainText[i]^ans[i-length]);
            }
        }
        return ans;

        /*
        byte[] ans = new byte[plainText.length];
        final int length = iv.length;
        int counter = plainText.length/length;
        int step = 1;
        for(int i = 0; i < length; i++){
            ans[i] = (byte)(plainText[i]^iv[i]);
        }
        while(step!=counter){
            for(int i = length*step; i < length*(step+1);i++){
                ans[i] = (byte)(plainText[i]^ans[i-length]);
            }
            step++;
        }
        return ans;

         */
    }

    // ============================================================================================
    // =================================== XOR'S ENCRYPTION =======================================
    // ============================================================================================

    /**
     * Method to encode a byte array using a XOR with a single byte long key
     * @param plainText the byte array representing the string to encode
     * @param key the byte we will use to XOR
     * @return an encoded byte array
     */
    public static byte[] xor(byte[] plainText, byte key) {
        byte[] ans = new byte[plainText.length];
        for(int i = 0; i<ans.length;i++){
            ans[i] = (byte)(plainText[i] ^ key);
        }
        return ans;
    }

    // ============================================================================================
    // =================================== ONETIME'S PAD ENCRYPTION ===============================
    // ============================================================================================

    /**
     * Method to encode a byte array using a one-time pad of the same length.
     *  The method XOR them together.
     * @param plainText the byte array representing the string to encode
     * @param pad the one-time pad
     * @return an encoded byte array
     */
    public static byte[] oneTimePad(byte[] plainText, byte[] pad) {
        byte[] ans = new byte[plainText.length];
        for(int i = 0; i<ans.length;i++){
            ans[i] = (byte)(plainText[i]^pad[i]);
        }
        return ans;
    }

    /**
     * Method to encode a byte array using a one-time pad
     * @param plainText Plain text to encode
     * @param pad Array containing the used pad after the execution
     * @param result Array containing the result after the execution
     */
    public static void oneTimePad(byte[] plainText, byte[] pad, byte[] result) {
        for(int i = 0; i<result.length;i++){
            result[i] = (byte)(plainText[i]^pad[i]);
        }
    }

}