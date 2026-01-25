import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class JcaKeyAgreementGenerateSecretTestFile {

    public void test() throws NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DiffieHellman"); // Noncompliant {{(PublicKeyEncryption) FFDH-3072}}
        SecretKey key = keyAgreement.generateSecret();
    }

}