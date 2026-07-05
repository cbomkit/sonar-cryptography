import java.security.SecureRandom;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcEAXBlockCipherTestFile {

    public static void test1() {
        // Generate a random key (for demonstration purposes)
        byte[] keyBytes = new byte[16];
        SecureRandom secureRandom = new SecureRandom(); // Noncompliant {{(PseudorandomNumberGenerator) PRNG}}
        secureRandom.nextBytes(keyBytes);

        // Create a block cipher engine
        BlockCipher aesEngine = new AESEngine(); // Noncompliant {{(BlockCipher) AES}}

        // Instantiate EAXBlockCipher with constructor
        EAXBlockCipher constructor =
                new EAXBlockCipher(aesEngine); // Noncompliant {{(AuthenticatedEncryption) AES-EAX}}

        // Initialize cipher with key and parameters
        KeyParameter keyParameter = new KeyParameter(keyBytes);
        AEADParameters parameters = new AEADParameters(keyParameter, 128, new byte[12]);
        constructor.init(true, parameters); // true for encryption, false for decryption
    }
}
