import java.security.SecureRandom;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RC6Engine;
import org.bouncycastle.crypto.modes.OCBBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcOCBBlockCipherTestFile {

    public static void test1() {
        // Generate a random key (for demonstration purposes)
        byte[] keyBytes = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(keyBytes);

        // Create a block cipher hash engine
        BlockCipher aesEngine = new AESEngine(); // Noncompliant {{(BlockCipher) AES}}

        // Create a block cipher main engine
        BlockCipher rc6Engine = new RC6Engine(); // Noncompliant {{(BlockCipher) RC6}}

        // Instantiate OCBBlockCipher with constructor
        OCBBlockCipher constructor =
                new OCBBlockCipher(aesEngine, rc6Engine); // Noncompliant {{(AuthenticatedEncryption) RC6-OCB}}

        // Initialize cipher with key and parameters
        KeyParameter keyParameter = new KeyParameter(keyBytes);
        AEADParameters parameters = new AEADParameters(keyParameter, 128, new byte[12]);
        constructor.init(true, parameters); // true for encryption, false for decryption
    }
}
