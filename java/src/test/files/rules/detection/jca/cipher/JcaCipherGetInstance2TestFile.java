import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class JcaCipher2TestFile {

    public void cipher2() {
        String transform = "AES/ECB/PKCS5Padding";
        Cipher c = Cipher.getInstance(transform, "BC"); // Noncompliant {{(BlockCipher) AES-128-ECB-PKCS5}}
    }
}