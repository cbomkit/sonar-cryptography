import javax.crypto.KeyAgreement;
import java.security.*;

public class JcaKeyAgreementGetInstanceTestFile {

    public void test() throws NoSuchAlgorithmException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DiffieHellman");  // Noncompliant {{(PublicKeyEncryption) FFDH-3072}}
    }

}