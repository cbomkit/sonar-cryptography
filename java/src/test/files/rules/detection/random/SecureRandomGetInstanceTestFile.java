import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SecureRandomGetInstanceTestFile {

    public void test() throws NoSuchAlgorithmException {
        byte[] seed = "1245".getBytes();
        SecureRandom seeded = new SecureRandom(seed); // Noncompliant {{(PseudorandomNumberGenerator) PRNG}}
        SecureRandom byName = SecureRandom.getInstance("DRBG"); // Noncompliant {{(PseudorandomNumberGenerator) PRNG}}
        SecureRandom strong = SecureRandom.getInstanceStrong(); // Noncompliant {{(PseudorandomNumberGenerator) PRNG}}
        SecureRandom def = new SecureRandom(); // Noncompliant {{(PseudorandomNumberGenerator) PRNG}}
    }
}
