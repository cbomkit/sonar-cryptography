import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class JcaIvParameterSpecTestFile {

    void test() {
        // Generate a random 256-bit key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES"); // Noncompliant {{(SecretKey) AES}}
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        // Generate a random 16-byte IV
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        // Encrypt
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Noncompliant {{(BlockCipher) AES-128-CBC-PKCS5}}
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));
    }
}