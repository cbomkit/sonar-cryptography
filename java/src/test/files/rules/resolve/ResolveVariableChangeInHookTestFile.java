import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;

class ResolveVariableChangeInHookTestFile {

    public Cipher getCipher(String type) throws NoSuchPaddingException, NoSuchAlgorithmException {
        final String type2 = type;
        return Cipher.getInstance(type2);
    }

    public void startCipherCascade() throws NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher c = getCipher("AES/ECB/NoPadding");  // Noncompliant {{(BlockCipher) AES-128-ECB}}
    }
}