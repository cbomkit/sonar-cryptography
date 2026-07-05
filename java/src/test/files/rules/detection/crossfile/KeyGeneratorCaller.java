package rules.detection.crossfile;

import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;

public class KeyGeneratorCaller {

    // Record-time-resolvable field argument -> detachable via symbol resolution at record time.
    private static final String ALGO = "Blowfish";

    // Literal argument -> detachable path.
    public SecretKey call() throws NoSuchAlgorithmException {
        return KeyGeneratorWrapper.generate("AES", 128); // Noncompliant {{(SecretKey) AES}}
    }

    // Field-constant argument -> detachable, resolved from the field at record time.
    public SecretKey callField() throws NoSuchAlgorithmException {
        return KeyGeneratorWrapper.generate(ALGO, 128); // Noncompliant {{(SecretKey) Blowfish}}
    }

    // NEW_ARRAY argument -> non-detachable, must resolve via the retained-tree fallback path.
    public SecretKey callWithArray() throws NoSuchAlgorithmException {
        return KeyGeneratorWrapper.generateWithIv("DES", 56, new byte[8]); // Noncompliant {{(SecretKey) DES}}
    }
}
