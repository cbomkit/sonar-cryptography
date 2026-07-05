import java.security.SecureRandom;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;

public class BcMLKEMGeneratorTestFile {

    public static void test() {
        // Create a SecureRandom instance
        SecureRandom random = new SecureRandom(); // Noncompliant {{(PseudorandomNumberGenerator) PRNG}}

        // Specify Kyber parameters
        MLKEMKeyParameters params = new MLKEMKeyParameters(true, MLKEMParameters.ml_kem_1024);

        // Initialize the key generator
        MLKEMGenerator kemGenerator = new MLKEMGenerator(random); // Noncompliant {{(KeyEncapsulationMechanism) ML-KEM-1024}}

        // Generate secret
        SecretWithEncapsulation secret =
                kemGenerator.generateEncapsulated(params);
    }

}