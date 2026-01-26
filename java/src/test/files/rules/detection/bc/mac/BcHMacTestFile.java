import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcHMacTestFile {
    private static void test1() {
        // Generate a random key
        byte[] key = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);

        // Initialize SHA-256 digest
        Digest digest = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}

        // Initialize HMac with the digest
        HMac hmac = new HMac(digest); // Noncompliant {{(Mac) HMAC-SHA-256}}

        // Compute HMAC
        hmac.init(new KeyParameter(key)); // Initialize MAC with the same key as the cipher

        // ...
    }
}
