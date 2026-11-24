import java.security.Key;
import javax.crypto.Cipher;

public class JcaCipherUnwrapTestFile {

    public void test(byte[] wrapped) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        Key key = cipher.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
    }
}
