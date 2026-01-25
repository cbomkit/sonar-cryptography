import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BcSM2EngineTestFile {

    public static void main(String[] args) throws Exception {
        // Add BouncyCastle provider
        Security.addProvider(new BouncyCastleProvider());

        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        // Noncompliant@-1 {{(Key) EC}}
        keyPairGenerator.initialize(new ECGenParameterSpec("sm2p256v1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Create SM2Engine instance
        SM2Engine sm2Engine = new SM2Engine(new SHA256Digest(), SM2Engine.Mode.C1C3C2);
        // Noncompliant@-1 {{(MessageDigest) SHA-256}} {{(PublicKeyEncryption) SM2}}

        // Encrypt
        byte[] plaintext = "Hello, SM2!".getBytes();
        sm2Engine.init(
                true,
                new ParametersWithRandom(
                        new ParametersWithID(
                                PublicKeyFactory.createKey(
                                        ((ECPublicKey) keyPair.getPublic()).getEncoded()),
                                null)));
        byte[] ciphertext = sm2Engine.processBlock(plaintext, 0, plaintext.length);
    }
}
