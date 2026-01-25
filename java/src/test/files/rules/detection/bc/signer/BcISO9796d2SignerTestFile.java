import java.math.BigInteger;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.ISO9796d1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.ISO9796d2Signer;

public class BcISO9796d2SignerTestFile {

    public static void test() {

        // Initialize the Digest
        Digest digest = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}

        // Initialize the Engine
        AsymmetricBlockCipher engine = new RSAEngine(); // Noncompliant {{(PublicKeyEncryption) RSA}}

        // Initialize the AsymmetricBlockCipher
        ISO9796d1Encoding cipher = new ISO9796d1Encoding(engine); // Noncompliant {{(PublicKeyEncryption) RSA}}

        // Initialize ISO9796d2Signer
        ISO9796d2Signer signer = new ISO9796d2Signer(cipher, digest, false);
        // Noncompliant@-1 {{(Signature) ISO 9796}}

        signer.init(true, new RSAKeyParameters(true, new BigInteger("0"), new BigInteger("1")));

        // Data to sign
        byte[] data = "Hello, World!".getBytes();

        // Perform signing
        signer.update(data, 0, data.length);
        try {
            byte[] signature = signer.generateSignature();
        } catch (CryptoException e) {
            e.printStackTrace();
        }
    }
}
