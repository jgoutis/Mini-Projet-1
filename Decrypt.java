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
 * <b>Task 2: </b>Utility class to decrypt a given cipher text.
 *
 * @author Hamza REMMAL (hamza.remmal@epfl.ch)
 * @version 1.0.0
 * @since 1.0.0
 */
public final class Decrypt {

    // DO NOT CHANGE THIS, MORE ON THAT ON WEEK 7
    private Decrypt(){}

    // ============================================================================================
    // ================================== CAESAR'S ENCRYPTION =====================================
    // ============================================================================================

    /**
     * Method to decode a byte array message using a single character key
     * <p>
     * @param cipher Cipher message to decode
     * @param key Key to decode with
     * @return decoded message
     */
    public static byte[] caesar(byte[] cipher, byte key) {
        final int alphaSize = 256;
        byte[] ans = new byte[cipher.length];
        for(int i = 0; i < ans.length; i++){
            ans[i] = (byte)((cipher[i] - key)%alphaSize);
        }
        return ans;
    }

    // ============================================================================================
    // =============================== VIGENERE'S ENCRYPTION ======================================
    // ============================================================================================

    /**
     * Method to encode a byte array using a byte array keyword
     * @param cipher Cipher message to decode
     * @param keyword Key to decode with
     * @return decoded message
     */
    public static byte[] vigenere(byte[] cipher, byte[] keyword) {
        final int alphaSize = 256;
        byte[] ans = new byte[cipher.length];
        for(int i = 0; i < ans.length; i++){
            ans[i] = (byte)((cipher[i] - keyword[i% keyword.length])%alphaSize);
        }
        return ans;
    }

    // ============================================================================================
    // =================================== CBC'S ENCRYPTION =======================================
    // ============================================================================================

    /**
     * Method to decode cbc-encrypted ciphers
     * @param cipher message to decode
     * @param iv the pad of size BLOCKSIZE we use to start the chain encoding
     * @return decoded message
     */
    public static byte[] cbc(byte[] cipher, byte[] iv) {
        byte[] ans = new byte[cipher.length];
        final int length = iv.length;
        int counter = cipher.length/length;
        int counter2 = cipher.length%length;
        int step = counter;
        if(counter2!= 0){
            for(int i = cipher.length-counter2; i<cipher.length; i++){
                ans[i] = (byte)(cipher[i]^cipher[i-length]);
            }
        }
        while(step!=1){
            for(int i = (length*step)-1; i > (length*(step-1))-1;i--){
                ans[i] = (byte)(cipher[i]^cipher[i-length]);
            }
            step--;
        }
        for(int i = 0; i < length; i++){
            ans[i] = (byte)(cipher[i]^iv[i]);
        }
        return ans;

        /*
        byte[] ans = new byte[cipher.length];
        final int length = iv.length;
        int counter = cipher.length/length;
        int step = 1;
        for(int i = 0; i < length; i++){
            ans[i] = (byte)(cipher[i]^iv[i]);
        }
        while(step!=counter){
            for(int i = length*step; i < length*(step+1);i++){
                ans[i] = (byte)(cipher[i]^ans[i-length]);
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
     * Method to decode xor-encrypted ciphers
     * @param cipher text to decode
     * @param key the byte we will use to XOR
     * @return decoded message
     */
    public static byte[] xor(byte[] cipher, byte key) {
        byte[] ans = new byte[cipher.length];
        for(int i = 0; i<ans.length;i++){
            ans[i] = (byte)(cipher[i] ^ key);
        }
        return ans;
    }

    // ============================================================================================
    // =================================== ONETIME'S PAD ENCRYPTION ===============================
    // ============================================================================================

    /**
     * Method to decode otp-encrypted ciphers
     * @param cipher text to decode
     * @param pad the one-time pad to use
     * @return decoded message
     */
    public static byte[] oneTimePad(byte[] cipher, byte[] pad) {
        byte[] ans = new byte[cipher.length];
        for(int i = 0; i<ans.length;i++){
            ans[i] = (byte)(cipher[i]^pad[i]);
        }
        return ans;
    }

}
