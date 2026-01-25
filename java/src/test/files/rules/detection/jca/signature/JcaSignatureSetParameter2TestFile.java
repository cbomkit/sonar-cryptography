import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class JcaSignatureSetParameter2TestFile {

    public void test() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        Signature signature = Signature.getInstance("RSASSA-PSS"); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
        signature.setParameter(new PSSParameterSpec("SHA3-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 20, 1));
    }
}