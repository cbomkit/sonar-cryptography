import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

/**
 * Regression test for issue #339: Detection location should point to the actual
 * call site,
 * not to the closing '*''/' of the next method's javadoc comment.
 *
 * <p>
 * This file simulates the Guava Hashing.java pattern where methods that wrap a
 * SecretKeySpec
 * constructor are separated by javadoc comments.
 */
public class PreciseIssueLocationTestFile {

    /**
     * Returns a hash function implementing HMAC-MD5 using the given byte array key.
     *
     * @param key the key material
     */
    public static Mac hmacMd5(byte[] key) throws Exception {
        SecretKeySpec spec = new SecretKeySpec(key, "HmacMD5"); // Noncompliant {{(SecretKey) HMAC}}

        return hmacMd5(spec);
    }

    /**
     * Returns a hash function implementing HMAC-MD5 using the given key.
     *
     * @param key the secret key
     * @throws IllegalArgumentException if the given key is inappropriate
     */
    public static Mac hmacMd5(Key key) throws Exception {
        Mac mac = Mac.getInstance("HmacMD5"); // Noncompliant {{(Mac) HMAC-MD5}}
        mac.init(key);
        return mac;
    }

    /**
     * Returns a hash function implementing HMAC-SHA256 using the given byte array
     * key.
     *
     * <p>
     * The returned hash function uses a {@link SecretKeySpec} created from the
     * given byte array
     * and the HmacSHA256 algorithm.
     *
     * @param key the key material of the secret key
     * @since 20.0
     */
    public static Mac hmacSha256(byte[] key) throws Exception {
        SecretKeySpec spec = new SecretKeySpec(key, "HmacSHA256"); // Noncompliant {{(SecretKey) HMAC}}

        return hmacSha256(spec);
    }

    /**
     * Returns a hash function implementing HMAC-SHA256 using the given key.
     *
     * @param key the secret key
     * @throws IllegalArgumentException if the given key is inappropriate for
     *                                  initializing this MAC
     * @since 20.0
     */
    public static Mac hmacSha256(Key key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256"); // Noncompliant {{(Mac) HMAC-SHA-256}}
        mac.init(key);
        return mac;
    }
}
