import java.math.BigInteger;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.kems.RSAKEMExtractor;
import org.bouncycastle.crypto.params.RSAKeyParameters;

public class BcRSAKEMExtractorTestFile {

    public static void test() {
        // Initialize the parameters
        int keyLen = 2048; // Key length in bits
        Digest digest = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}
        DerivationFunction kdf =
                new HKDFBytesGenerator(digest); // Your DerivationFunction implementation
        // Noncompliant@-1 {{(KeyDerivationFunction) HKDF-SHA-256}}

        // Create a RSAKeyParameters object named privParams
        RSAKeyParameters privParams =
                new RSAKeyParameters(true, new BigInteger("1"), new BigInteger("2"));

        // Instantiate the RSAKEMExtractor
        RSAKEMExtractor extractor =
                new RSAKEMExtractor(privParams, keyLen, kdf); // Noncompliant {{(KeyEncapsulationMechanism) RSA-KEM}}

        // Extract the shared secret key using the private key parameters
        byte[] sharedSecret = extractor.extractSecret(null);

        // ...
    }
}
