import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcCCMBlockCipherTestFile {

    public static void test1() {
        // Generate a random key (for demonstration purposes)
        byte[] keyBytes = new byte[16];

        // Create a block cipher engine
        BlockCipher aesEngine = new AESEngine(); // Noncompliant {{(BlockCipher) AES}}

        // Instantiate CCMBlockCipher with constructor
        CCMBlockCipher constructor =
                new CCMBlockCipher(aesEngine); // Noncompliant {{(AuthenticatedEncryption) AES-CCM}}

        // Initialize cipher with key and parameters
        KeyParameter keyParameter = new KeyParameter(keyBytes);
        AEADParameters parameters = new AEADParameters(keyParameter, 128, new byte[12]);
        constructor.init(true, parameters); // true for encryption, false for decryption
    }

    public static void test2() {
        // Generate a random key (for demonstration purposes)
        byte[] keyBytes = new byte[16];

        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES}}

        // Instantiate CCMBlockCipher with newInstance() method
        CCMBlockCipher newInstance =
                (CCMBlockCipher)
                        CCMBlockCipher.newInstance(aesEngine); // Noncompliant {{(AuthenticatedEncryption) AES-CCM}}

        // Initialize cipher with key and parameters
        KeyParameter keyParameter = new KeyParameter(keyBytes);
        AEADParameters parameters = new AEADParameters(keyParameter, 128, new byte[12]);
        newInstance.init(true, parameters); // true for encryption, false for decryption
    }
}
