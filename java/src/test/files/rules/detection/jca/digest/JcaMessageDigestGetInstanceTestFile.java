import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class JcaMessageDigestGetInstanceTestFile {

    public void test() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-512/224"); // Noncompliant {{(MessageDigest) SHA-512/224}}
    }

}