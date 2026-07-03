import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AsconEngine;
import org.bouncycastle.crypto.engines.Grain128AEADEngine;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcAEADCipherEngineTestFile {

    public static void test1() {

        // Example key (256-bit key)
        byte[] key = new byte[32]; // 32 bytes = 256 bits
        // Initialize the key with random bytes (for demonstration purposes)
        // In practice, you should use a secure random generator to generate the key
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (Math.random() * 256);
        }

        // Initialize the AsconEngine
        AsconEngine asconEngine =
                new AsconEngine(AsconEngine.AsconParameters.ascon128); // Noncompliant {{(AuthenticatedEncryption) Ascon-AEAD128}}

        // Initialize the key parameter with the provided key
        CipherParameters keyParam = new KeyParameter(key);
        asconEngine.init(true, keyParam); // true for encryption, false for decryption

        // Encrypt the plaintext
        // ...
    }

    public static void test2() {

        // Example key (256-bit key)
        byte[] key = new byte[32]; // 32 bytes = 256 bits
        // Initialize the key with random bytes (for demonstration purposes)
        // In practice, you should use a secure random generator to generate the key
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (Math.random() * 256);
        }

        // Initialize the Grain128AEADEngine
        Grain128AEADEngine engine =
                new Grain128AEADEngine(); // Noncompliant {{(AuthenticatedEncryption) Grain-128AEAD}}

        // Initialize the key parameter with the provided key
        CipherParameters keyParam = new KeyParameter(key);
        engine.init(true, keyParam); // true for encryption, false for decryption

        // Encrypt the plaintext
        // ...
    }
}
