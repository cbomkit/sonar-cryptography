import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class JcaMessageDigestGetInstanceMd5TestFile {

    public void test() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("MD5"); // Noncompliant {{(MessageDigest) MD5}}
    }
}
