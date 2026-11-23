import java.security.SecureRandom;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.CCMParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcCCMParametersTestFile {

    public static void testCCMParameters() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES}}

        // Generate a random key (for demonstration purposes)
        byte[] keyBytes = new byte[16];
        SecureRandom secureRandom = new SecureRandom(); // Noncompliant {{(PseudorandomNumberGenerator) PRNG}}
        secureRandom.nextBytes(keyBytes);

        // Initialize cipher with key and parameters
        KeyParameter keyParameter = new KeyParameter(keyBytes);
        CCMParameters parameters = new CCMParameters(keyParameter, 128, new byte[12], new byte[12]);

        aesEngine.init(true, parameters); // true for encryption, false for decryption
    }
}
