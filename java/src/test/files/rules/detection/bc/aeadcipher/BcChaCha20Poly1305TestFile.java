import java.security.SecureRandom;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcChaCha20Poly1305TestFile {

    public static void test1() {
        // Generate a random key (for demonstration purposes)
        byte[] keyBytes = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(keyBytes);

        // Instantiate ChaCha20Poly1305 with constructor
        ChaCha20Poly1305 constructor = new ChaCha20Poly1305(); // Noncompliant {{(AuthenticatedEncryption) ChaCha20-Poly1305}}

        // Initialize cipher with key and parameters
        KeyParameter keyParameter = new KeyParameter(keyBytes);
        AEADParameters parameters = new AEADParameters(keyParameter, 128, new byte[12]);
        constructor.init(true, parameters); // true for encryption, false for decryption
    }

    public static void test2() {
        // Generate a random key (for demonstration purposes)
        byte[] keyBytes = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(keyBytes);

        // Instantiate ChaCha20Poly1305 with constructor
        ChaCha20Poly1305 constructor =
                new ChaCha20Poly1305(new Poly1305()); // Noncompliant {{(AuthenticatedEncryption) ChaCha20Poly1305}}
                // Noncompliant@-1 {{(Mac) Poly1305}}

        // Initialize cipher with key and parameters
        KeyParameter keyParameter = new KeyParameter(keyBytes);
        AEADParameters parameters = new AEADParameters(keyParameter, 128, new byte[12]);
        constructor.init(true, parameters); // true for encryption, false for decryption
    }
}
