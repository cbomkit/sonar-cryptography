import javax.crypto.spec.DHGenParameterSpec;
import java.security.AlgorithmParameterGenerator;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

public class JcaDHGenParameterSpecTestFile {

    public void test() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DiffieHellman");  // Noncompliant {{(PublicKeyEncryption) FFDH-2048}}
        DHGenParameterSpec genParameterSpec = new DHGenParameterSpec(2048, 128);
        paramGen.init(genParameterSpec);
    }
}