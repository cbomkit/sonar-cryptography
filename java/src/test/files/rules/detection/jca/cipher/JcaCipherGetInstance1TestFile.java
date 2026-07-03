import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class JcaCipher1TestFile {

    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    public void cipher1() {
        Cipher c = Cipher.getInstance(TRANSFORMATION); // Noncompliant {{(BlockCipher) AES-128-ECB-PKCS5}}
    }

}