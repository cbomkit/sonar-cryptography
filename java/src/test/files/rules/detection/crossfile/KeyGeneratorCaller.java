package rules.detection.crossfile;

import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;

public class KeyGeneratorCaller {
    public SecretKey call() throws NoSuchAlgorithmException {
        return KeyGeneratorWrapper.generate("AES", 128); // Noncompliant {{(SecretKey) AES}}
    }
}
