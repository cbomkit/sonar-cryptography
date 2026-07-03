import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;

public class BcMLKEMGeneratorTestFile {

    public static void test() {
        // Specify Kyber parameters
        MLKEMKeyParameters params = new MLKEMKeyParameters(true, MLKEMParameters.ml_kem_1024);

        // Initialize the key generator
        MLKEMGenerator kemGenerator = new MLKEMGenerator(null); // Noncompliant {{(KeyEncapsulationMechanism) ML-KEM-1024}}

        // Generate secret
        SecretWithEncapsulation secret =
                kemGenerator.generateEncapsulated(params);
    }

}