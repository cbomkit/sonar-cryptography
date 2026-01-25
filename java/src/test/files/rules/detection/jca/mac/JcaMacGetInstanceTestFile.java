import javax.crypto.Mac;
import java.security.NoSuchAlgorithmException;

public class JcaMacGetInstanceTestFile {
    public void test() throws NoSuchAlgorithmException {
        Mac mac = Mac.getInstance("HmacSHA3-384");  // Noncompliant {{(Mac) HMAC-SHA-3-384}}
    }
}