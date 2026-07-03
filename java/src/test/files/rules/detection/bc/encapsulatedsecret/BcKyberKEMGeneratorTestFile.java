import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;

public class BcKyberKEMGeneratorTestFile {

    public static void test() {
        // Specify Kyber parameters
        KyberKeyGenerationParameters params =
                new KyberKeyGenerationParameters(null, KyberParameters.kyber512);

        // Initialize the Kyber key generator
        KyberKEMGenerator kemGenerator = new KyberKEMGenerator(null); // Noncompliant {{(KeyEncapsulationMechanism) Kyber}}

        // Generate secret
        SecretWithEncapsulation secret =
                kemGenerator.generateEncapsulated(params);

        // ...
    }
}
