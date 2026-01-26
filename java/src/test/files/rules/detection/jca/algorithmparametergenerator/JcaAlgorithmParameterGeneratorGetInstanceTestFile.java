import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

public class JcaAlgorithmParameterGeneratorGetInstanceTestFile {

    public void test() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DiffieHellman"); // Noncompliant {{(PublicKeyEncryption) FFDH-3072}}
    }
}