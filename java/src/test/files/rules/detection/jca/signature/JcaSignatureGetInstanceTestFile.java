import java.security.NoSuchAlgorithmException;
import java.security.Signature;

public class JcaSignatureGetInstanceTestFile {

    public void test() throws NoSuchAlgorithmException {
        Signature signature = Signature.getInstance("SHA384withDSA"); // Noncompliant {{(Signature) SHA-384withDSA}}
    }
}