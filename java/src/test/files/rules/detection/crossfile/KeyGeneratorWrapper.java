package rules.detection.crossfile;

import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class KeyGeneratorWrapper {
    public static SecretKey generate(String algo, int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algo);
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    // Extra byte[] parameter so a caller passing `new byte[N]` makes the recorded call carry a
    // NEW_ARRAY argument -> the detach predicate must keep this call on the retained-tree path.
    public static SecretKey generateWithIv(String algo, int keySize, byte[] iv)
            throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algo);
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }
}
