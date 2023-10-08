import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class FalconDemo1 {
    static {
        System.loadLibrary("falcon1");
    }
    private static native KeyPair keygens();
    private static native byte[] sign(byte[] message, byte[] privateKey, byte[] publicKey);
    private static native boolean verify(byte[] message, byte[] signature, byte[] publicKey);

    public static void main(String[] args) throws NoSuchAlgorithmException {
        KeyPair keyPair = keygens();

        // Sign a message using the private key
        byte[] message = "Hello, world!".getBytes();
        byte[] signature = sign(message, keyPair.getPrivate().getEncoded(), keyPair.getPublic().getEncoded());

        // Verify the signature using the public key
        boolean verified = verify(message, signature, keyPair.getPublic().getEncoded());

        System.out.println("Signature verified: " + verified);
    }

}