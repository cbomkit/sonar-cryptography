import java.math.BigInteger;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.kems.ECIESKEMExtractor;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;

public class BcECIESKEMExtractorTestFile {

    public static void test() {
        // Initialize the parameters
        int keyLen = 2048; // Key length in bits
        Digest digest = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}
        DerivationFunction kdf =
                new HKDFBytesGenerator(digest); // Your DerivationFunction implementation
        // Noncompliant@-1 {{(KeyDerivationFunction) HKDF-SHA-256}}

        // Create a RSAKeyParameters object named privParams
        ECPrivateKeyParameters privParams = new ECPrivateKeyParameters(new BigInteger("1"), null);

        // Instantiate the ECIESKEMExtractor
        ECIESKEMExtractor extractor =
                new ECIESKEMExtractor(privParams, keyLen, kdf); // Noncompliant {{(KeyEncapsulationMechanism) ECIES-KEM}}

        // Extract the shared secret key using the private key parameters
        byte[] sharedSecret = extractor.extractSecret(null);

        // ...
    }
}
