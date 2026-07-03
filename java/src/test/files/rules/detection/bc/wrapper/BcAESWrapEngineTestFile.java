import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcAESWrapEngineTestFile {
    public static void test() {
        // Generate a random AES key to be wrapped
        byte[] keyToWrap = new byte[16]; // 128-bit key

        // Generate a wrapping key
        byte[] wrappingKey = new byte[16]; // 128-bit key

        // Wrap the key
        AESWrapEngine wrapper = new AESWrapEngine(); // Noncompliant {{(KeyWrap) AES}}
        KeyParameter keyParameter = new KeyParameter(wrappingKey);
        wrapper.init(true, keyParameter);

        // Perform the wrapping
        byte[] wrappedKey = wrapper.wrap(keyToWrap, 0, keyToWrap.length);
        // The wrappedKey now contains the encrypted version of keyToWrap
    }
}
