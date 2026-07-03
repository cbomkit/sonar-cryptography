import java.security.NoSuchAlgorithmException;
import java.security.Signature;

public class JcaSignatureGetInstanceTestFile {

    public void test() throws NoSuchAlgorithmException {
        Signature signature = Signature.getInstance("SHA384withDSA"); // Noncompliant {{(Signature) DSA-2048-SHA-384}}
    }
}