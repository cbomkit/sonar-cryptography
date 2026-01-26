import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.PSSParameterSpec;

public class JcaSignatureSetParameterTestFile {

    public void test() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        Signature signature = Signature.getInstance("RSASSA-PSS"); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
        signature.setParameter(new PSSParameterSpec(20));
    }
}