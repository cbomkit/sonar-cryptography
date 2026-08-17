import java.security.SecureRandom;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;

public class BcKyberKEMGeneratorTestFile {

    public static void test() {
        // Create a SecureRandom instance
        SecureRandom random = new SecureRandom(); // Noncompliant {{(PseudorandomNumberGenerator) PRNG}}

        // Specify Kyber parameters
        KyberKeyGenerationParameters params =
                new KyberKeyGenerationParameters(random, KyberParameters.kyber512);

        // Initialize the Kyber key generator
        KyberKEMGenerator kemGenerator = new KyberKEMGenerator(random); // Noncompliant {{(KeyEncapsulationMechanism) Kyber}}

        // Generate secret
        SecretWithEncapsulation secret =
                kemGenerator.generateEncapsulated(params);

        // ...
    }
}
