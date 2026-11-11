import java.security.SecureRandom;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.modes.GCMSIVBlockCipher;
import org.bouncycastle.crypto.modes.gcm.GCMMultiplier;
import org.bouncycastle.crypto.modes.gcm.Tables8kGCMMultiplier;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcGCMSIVBlockCipherTestFile {

    public static void test1() {
        // Generate a random key (for demonstration purposes)
        byte[] keyBytes = new byte[16];
        SecureRandom secureRandom = new SecureRandom(); // Noncompliant {{(PseudorandomNumberGenerator) PRNG}}
        secureRandom.nextBytes(keyBytes);

        // Instantiate GCMSIVBlockCipher with constructor
        GCMSIVBlockCipher constructor =
                new GCMSIVBlockCipher(); // Noncompliant {{(AuthenticatedEncryption) AES-GCM-SIV}}

        // Initialize cipher with key and parameters
        KeyParameter keyParameter = new KeyParameter(keyBytes);
        AEADParameters parameters = new AEADParameters(keyParameter, 128, new byte[12]);
        constructor.init(true, parameters); // true for encryption, false for decryption
    }

    public static void test2() {
        // Generate a random key (for demonstration purposes)
        byte[] keyBytes = new byte[16];
        SecureRandom secureRandom = new SecureRandom(); // Noncompliant {{(PseudorandomNumberGenerator) PRNG}}
        secureRandom.nextBytes(keyBytes);

        // Create a block cipher engine
        BlockCipher aesEngine = new RijndaelEngine(); // Noncompliant {{(BlockCipher) AES}}

        // Instantiate GCMSIVBlockCipher with constructor
        GCMSIVBlockCipher constructor =
                new GCMSIVBlockCipher(aesEngine); // Noncompliant {{(AuthenticatedEncryption) AES-GCM-SIV}}

        // Initialize cipher with key and parameters
        KeyParameter keyParameter = new KeyParameter(keyBytes);
        AEADParameters parameters = new AEADParameters(keyParameter, 128, new byte[12]);
        constructor.init(true, parameters); // true for encryption, false for decryption
    }

    public static void test3() {
        // Generate a random key (for demonstration purposes)
        byte[] keyBytes = new byte[16];
        SecureRandom secureRandom = new SecureRandom(); // Noncompliant {{(PseudorandomNumberGenerator) PRNG}}
        secureRandom.nextBytes(keyBytes);

        // Create a block cipher engine
        BlockCipher aesEngine = new AESEngine(); // Noncompliant {{(BlockCipher) AES}}

        // Create a GCMMultiplier (e.g., Tables8kGCMMultiplier)
        GCMMultiplier multiplier = new Tables8kGCMMultiplier();

        // Instantiate GCMSIVBlockCipher with constructor
        GCMSIVBlockCipher constructor =
                new GCMSIVBlockCipher(aesEngine, multiplier); // Noncompliant {{(AuthenticatedEncryption) AES-GCM-SIV}}

        // Initialize cipher with key and parameters
        KeyParameter keyParameter = new KeyParameter(keyBytes);
        AEADParameters parameters = new AEADParameters(keyParameter, 128, new byte[12]);
        constructor.init(true, parameters); // true for encryption, false for decryption
    }
}
