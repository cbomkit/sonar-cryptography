import java.security.SecureRandom;
import org.bouncycastle.crypto.engines.DSTU7624WrapEngine;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcDSTU7624WrapEngineTestFile {
    public static void test() {
        // Generate a random AES key to be wrapped
        SecureRandom random = new SecureRandom(); // Noncompliant {{(PseudorandomNumberGenerator) PRNG}}
        byte[] keyToWrap = new byte[16]; // 128-bit key
        random.nextBytes(keyToWrap);

        // Generate a wrapping key
        byte[] wrappingKey = new byte[32]; // 256-bit key
        random.nextBytes(wrappingKey);

        // Wrap the key (block size: 256 bits)
        DSTU7624WrapEngine wrapper = new DSTU7624WrapEngine(256); // Noncompliant {{(KeyWrap) Kalyna-256}}
        KeyParameter keyParameter = new KeyParameter(wrappingKey);
        wrapper.init(true, keyParameter);

        
        // Perform the wrapping
        byte[] wrappedKey = wrapper.wrap(keyToWrap, 0, keyToWrap.length);
        // The wrappedKey now contains the encrypted version of keyToWrap
    }
}
