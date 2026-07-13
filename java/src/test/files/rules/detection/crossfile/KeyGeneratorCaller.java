package rules.detection.crossfile;

import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;

public class KeyGeneratorCaller {

    // Record-time-resolvable field argument -> detachable via symbol resolution at record time.
    private static final String ALGO = "Blowfish";

    // Literal argument -> detachable path. Detached cross-file detections produce a CBOM node but no
    // tree-based SonarQube issue, so there is no Noncompliant marker here (asserted via nodes).
    public SecretKey call() throws NoSuchAlgorithmException {
        return KeyGeneratorWrapper.generate("AES", 128);
    }

    // Field-constant argument -> detachable, resolved from the field at record time.
    public SecretKey callField() throws NoSuchAlgorithmException {
        return KeyGeneratorWrapper.generate(ALGO, 128);
    }

    // NEW_ARRAY argument -> non-detachable, resolves via the retained-tree fallback path, which keeps
    // the live scan context and therefore still raises the SonarQube issue.
    public SecretKey callWithArray() throws NoSuchAlgorithmException {
        return KeyGeneratorWrapper.generateWithIv("DES", 56, new byte[8]); // Noncompliant {{(SecretKey) DES}}
    }
}
