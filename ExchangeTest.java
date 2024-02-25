import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Assignment 1.
 * Coded with Java 17.
 */
public class ExchangeTest {

    public static void main(String[] args) {
        BlockingQueue<byte[]> alexQ = new LinkedBlockingQueue<>();
        BlockingQueue<byte[]> bobQ = new LinkedBlockingQueue<>();

        Alex alex = new Alex(alexQ);
        Bob bob = new Bob(bobQ);

        // generating RSA key pairs
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");

            kpg.initialize(512);

            KeyPair kp = kpg.generateKeyPair();
            alex.setPublicKey(kp.getPublic());
            alex.setPrivateKey(kp.getPrivate());

            kp = kpg.generateKeyPair();
            bob.setPublicKey(kp.getPublic());
            bob.setPrivateKey(kp.getPrivate());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        // initializing threads
        Thread alexThread = new Thread(() -> {
            alex.generateKey();
            alex.sendKey(bob);
            alex.sendMessage(bob, "Let us have a meeting tomorrow at 4".getBytes());
            alex.receiveReply();
        });

        Thread bobThread = new Thread(() -> {
            bob.receiveKey(alex.getPublicKey());
            bob.receiveMessage();
            bob.sendReply("Yes, I can meet you at Student Union".getBytes(), alexQ);
        });

        alexThread.start();
        bobThread.start();

        // waiting for threads to finish
        try {
            alexThread.join();
            bobThread.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

}
