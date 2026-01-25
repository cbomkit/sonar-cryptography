import java.security.SecureRandom;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.kems.RSAKEMGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class BcRSAKEMGeneratorTestFile {

        public static void main(String[] args) {
            // Initialize the parameters
            int keyLen = 2048; // Key length in bits
            SecureRandom rnd = new SecureRandom(); // Secure random number generator
            Digest digest = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}
            DerivationFunction kdf =
                    new HKDFBytesGenerator(digest); // Your DerivationFunction implementation
            // Noncompliant@-1 {{(KeyDerivationFunction) HKDF-SHA-256}}
    
            // Initialize the RSAKEMGenerator
            RSAKEMGenerator kemGenerator =
                    new RSAKEMGenerator(keyLen, kdf, rnd); // Noncompliant {{(KeyEncapsulationMechanism) RSA-KEM}}
    
            // Generate secret
            SecretWithEncapsulation secret =
                    kemGenerator.generateEncapsulated(new AsymmetricKeyParameter(true));
        }
    }