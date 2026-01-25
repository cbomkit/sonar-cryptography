import javax.crypto.KeyAgreement;
import javax.crypto.spec.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class JcaKeyAgreementInitTestFile {
    public void test() throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DiffieHellman");  // Noncompliant {{(PublicKeyEncryption) FFDH-512}}
        keyAgreement.init(null, new DHParameterSpec(
                new BigInteger("9708102954833850385429735875923118698675232975312319039401641572679349867933157991841270959296437077051734595809836247517279020686405390233910225592049587"),
                new BigInteger("2")));
    }

}