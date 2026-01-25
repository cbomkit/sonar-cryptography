import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class JcaSignatureSetParameter3TestFile {

    public void test() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        Signature signature = Signature.getInstance("RSASSA-PSS"); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
        signature.setParameter(new PSSParameterSpec("SHA3-256", "MGF1", MGF1ParameterSpec.SHA1, 20, 1));
    }
}