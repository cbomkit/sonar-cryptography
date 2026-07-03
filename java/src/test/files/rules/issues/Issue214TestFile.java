import java.security.NoSuchAlgorithmException;
import java.security.Signature;

public class JcaSignatureGetInstanceTestFile {

    public void test() throws NoSuchAlgorithmException {
        Signature signature = Signature.getInstance("SHA1withRSA"); // Noncompliant {{(Signature) RSA-PKCS1-1.5-SHA-1}}
    }
}