import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

public class JcaSignatureActionSignTestFile {
    public void test() throws NoSuchAlgorithmException, SignatureException {
        Signature signature = Signature.getInstance("SHA384withDSA"); // Noncompliant {{(Signature) DSA-2048-SHA-384}}
        signature.sign();
    }

}