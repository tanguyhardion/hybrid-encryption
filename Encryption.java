import java.security.Key;
import java.util.Base64;

import javax.crypto.Cipher;

public class Encryption {

    /**
     * Encrypts a byte array using a cipher and a key.
     * Encodes the result using Base64.
     * 
     * @param s - the byte array to encrypt
     * @param c - the cipher to use
     * @param key - the key to use
     * @return the encrypted and encoded byte array
     * @throws Exception if the encryption fails
     */
    public static byte[] encrypt(byte[] s, Cipher c, Key key) throws Exception {
        c.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getMimeEncoder().encode(c.doFinal(s));
    }

    /**
     * Decrypts a byte array using a cipher and a key.
     * Decodes the input using Base64.
     *
     * @param s - the byte array to decrypt
     * @param c - the cipher to use
     * @param key - the key to use
     * @return the decrypted and decoded byte array
     * @throws Exception if the decryption fails
     */
    public static byte[] decrypt(byte[] s, Cipher c, Key key) throws Exception {
        c.init(Cipher.DECRYPT_MODE, key);
        return c.doFinal(Base64.getMimeDecoder().decode(s));
    }

}
