import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.concurrent.BlockingQueue;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Bob {

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private SecretKey secretKey;
    private BlockingQueue<byte[]> bobQ;

    public Bob(BlockingQueue<byte[]> bobQ) {
        this.bobQ = bobQ;
    }

    public void receiveKey(PublicKey alexPublicKey) {
        try {
            // retrieving the signed key
            byte[] signedKey = bobQ.take();

            // retrieving the encrypted secret key
            byte[] encryptedKey = bobQ.take();

            // verifying the signature using Alex's public key
            Signature signature = Signature.getInstance("SHA256WithRSA");
            signature.initVerify(alexPublicKey);
            signature.update(encryptedKey);
            boolean verified = signature.verify(signedKey);

            if (verified) {
                // decrypting the secret key using Bob's private key
                byte[] decryptedKey = Encryption.decrypt(encryptedKey, Cipher.getInstance("RSA/ECB/PKCS1Padding"),
                        this.privateKey);
                SecretKey key = new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");
                this.setSecretKey(key);
                System.out.println("Alex's signature was verified.");
            } else {
                System.out.println("Alex's signature could not be verified.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void receiveMessage() {
        try {
            // retrieving the encrypted message
            byte[] message = bobQ.take();

            // decrypting the message using the secret key
            byte[] decryptedMessage = Encryption.decrypt(message, Cipher.getInstance("AES/ECB/PKCS5Padding"),
                    this.secretKey);
            String decryptedMessageString = new String(decryptedMessage);

            System.out.println("Bob received a message: " + decryptedMessageString);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void sendReply(byte[] reply, BlockingQueue<byte[]> alexQ) {
        try {
            // encrypting the reply using the secret key
            Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            byte[] encryptedReply = Encryption.encrypt(reply, aesCipher, this.secretKey);

            // sending the encrypted reply to Alex Q
            alexQ.put(encryptedReply);
            System.out.println("Reply encrypted and sent to Alex.");
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

    public BlockingQueue<byte[]> getBobQ() {
        return bobQ;
    }

}
