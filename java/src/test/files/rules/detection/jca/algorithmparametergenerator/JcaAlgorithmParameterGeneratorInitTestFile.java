import java.security.AlgorithmParameterGenerator;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

public class JcaAlgorithmParameterGeneratorInitTestFile {

    void test() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DiffieHellman"); // Noncompliant {{(PublicKeyEncryption) FFDH-2048}}
        paramGen.init(2048);
    }
}