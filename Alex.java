import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.concurrent.BlockingQueue;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Alex {

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private SecretKey secretKey;
    private BlockingQueue<byte[]> alexQ;

    public Alex(BlockingQueue<byte[]> alexQ) {
        this.alexQ = alexQ;
    }

    public void generateKey() {
        try {
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(256);
            SecretKey key = keygen.generateKey();
            this.setSecretKey(key);
            System.out.println("Secret key generated.");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void sendKey(Bob bob) {
        try {
            // encrypting the secret key using Bob's public key
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            byte[] encryptedKey = Encryption.encrypt(this.secretKey.getEncoded(), rsaCipher,
                    bob.getPublicKey());

            // signing the encrypted secret key using Alex's private key
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(this.privateKey);
            signature.update(encryptedKey);
            byte[] signedKey = signature.sign();

            // sending the concatenated signed key and the encrypted secret key to Bob Q
            bob.getBobQ().put(signedKey);
            bob.getBobQ().put(encryptedKey);
            System.out.println("Secret key signed, encrypted and sent to Bob.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void sendMessage(Bob bob, byte[] message) {
        try {
            // encrypting the message using the secret key
            Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            byte[] encryptedMessage = Encryption.encrypt(message, aesCipher, this.secretKey);

            // sending the encrypted message to Bob Q
            bob.getBobQ().put(encryptedMessage);
            System.out.println("Message encrypted and sent to Bob.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void receiveReply() {
        try {
            // retrieving the encrypted reply
            byte[] reply = alexQ.take();

            // decrypting the reply using the secret key
            byte[] decryptedReply = Encryption.decrypt(reply, Cipher.getInstance("AES/ECB/PKCS5Padding"),
                    this.secretKey);
            String decryptedReplyString = new String(decryptedReply);

            System.out.println("Alex received a reply: " + decryptedReplyString);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public void setSecretKey(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    public BlockingQueue<byte[]> getAlexQ() {
        return alexQ;
    }

}
