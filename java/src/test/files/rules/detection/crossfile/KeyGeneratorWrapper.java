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
}
