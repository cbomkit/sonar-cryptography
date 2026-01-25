import java.security.SecureRandom;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.kems.ECIESKEMGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class BcECIESKEMGeneratorTestFile {

    public static void main(String[] args) {
        // Initialize the parameters
        int keyLen = 2048; // Key length in bits

        SecureRandom rnd = new SecureRandom(); // Secure random number generator

        Digest digest = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}

        DerivationFunction kdf = new HKDFBytesGenerator(digest); // Noncompliant {{(KeyDerivationFunction) HKDF-SHA-256}}

        // Initialize the ECIESKEMGenerator
        ECIESKEMGenerator kemGenerator =
                new ECIESKEMGenerator(keyLen, kdf, rnd, true, true, true); // Noncompliant {{(KeyEncapsulationMechanism) ECIES-KEM}}

        // Generate secret
        SecretWithEncapsulation secret =
                kemGenerator.generateEncapsulated(new AsymmetricKeyParameter(true));
    }
}
