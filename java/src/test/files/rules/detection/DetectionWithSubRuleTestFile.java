import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class DetectionWithSubRuleTestFile {

    void test() throws Exception {
        Cipher cipher = Cipher.getInstance("AES"); // Noncompliant {{AES}}
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec("0123456789ABCDEF".getBytes(), "AES")); // Noncompliant {{128}} {{2}} {{AES}}
    }
}