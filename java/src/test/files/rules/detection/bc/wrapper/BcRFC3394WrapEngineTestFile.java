import java.security.SecureRandom;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.RFC3394WrapEngine;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcRFC3394WrapEngineTestFile {

    public static void test1() {
        // Generate a random AES key to be wrapped
        SecureRandom random = new SecureRandom(); // Noncompliant {{(PseudorandomNumberGenerator) PRNG}}
        byte[] keyToWrap = new byte[16]; // 128-bit key
        random.nextBytes(keyToWrap);

        // Generate a wrapping key
        byte[] wrappingKey = new byte[16]; // 128-bit key
        random.nextBytes(wrappingKey);

        // Wrap the key
        AESFastEngine aesEngine = new AESFastEngine(); // Noncompliant {{(BlockCipher) AES}}
        RFC3394WrapEngine wrapper = new RFC3394WrapEngine(aesEngine); // Noncompliant {{(KeyWrap) AES}}
        KeyParameter keyParameter = new KeyParameter(wrappingKey);
        wrapper.init(true, keyParameter);

        // ...
    }

    public static void test2() {
        // Generate a random AES key to be wrapped
        SecureRandom random = new SecureRandom(); // Noncompliant {{(PseudorandomNumberGenerator) PRNG}}
        byte[] keyToWrap = new byte[16]; // 128-bit key
        random.nextBytes(keyToWrap);

        // Generate a wrapping key
        byte[] wrappingKey = new byte[16]; // 128-bit key
        random.nextBytes(wrappingKey);

        // Wrap the key in the forward direction
        AESFastEngine aesEngine = new AESFastEngine(); // Noncompliant {{(BlockCipher) AES}}
        RFC3394WrapEngine forwardWrapper = // Forward direction
                new RFC3394WrapEngine(aesEngine, false); // Noncompliant {{(KeyWrap) AES}}
        KeyParameter forwardKeyParameter = new KeyParameter(wrappingKey);
        forwardWrapper.init(true, forwardKeyParameter);

        // ...
    }
}
