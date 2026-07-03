import java.security.SecureRandom;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcAEADParametersTestFile {

    public static void testAEADParameters() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES-256}}

        // Generate a random key (for demonstration purposes)
        byte[] keyBytes = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(keyBytes);

        // Initialize cipher with key and parameters
        KeyParameter keyParameter = new KeyParameter(new byte[12], 0, 256);
        AEADParameters parameters = new AEADParameters(keyParameter, 128, new byte[12]);

        aesEngine.init(true, parameters); // true for encryption, false for decryption
    }
}
