import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

public class JcaSignatureActionVerifyTestFile {

    public void test() throws NoSuchAlgorithmException, SignatureException {
        Signature signature = Signature.getInstance("SHA384withDSA"); // Noncompliant {{(Signature) SHA-384withDSA}}
        signature.verify(new byte[10]);
    }

}