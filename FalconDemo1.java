import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class FalconDemo1 {
    static {
        System.loadLibrary("falcon1");
    }
    private static native KeyPair keygens();
    private static native byte[] sign(byte[] privateKey, byte[] message, int msgLength, byte[] sig);
    private static native boolean verify(byte[] publicKey, byte[] message,int msgLength, byte[] signature);

    public static void main(String[] args) throws NoSuchAlgorithmException {
        KeyPair keyPair = keygens();

        // Sign a message using the private key
        byte[] message = "Hello, world!".getBytes();
        byte[] signature = sign(keyPair.getPrivate().getEncoded(), message, message.length, new byte[666]);

        // Verify the signature using the public key
        boolean verified = verify(keyPair.getPublic().getEncoded(), message, message.length, signature);

        System.out.println("Signature verified: " + verified);
    }

}