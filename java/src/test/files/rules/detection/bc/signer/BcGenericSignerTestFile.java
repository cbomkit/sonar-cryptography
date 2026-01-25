import java.math.BigInteger;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.GenericSigner;

public class BcGenericSignerTestFile {

    public static void test() {

        // Initialize the AsymmetricBlockCipher engine
        AsymmetricBlockCipher engine = new RSAEngine(); // Noncompliant {{(PublicKeyEncryption) RSA}}

        // Initialize the Digest
        Digest digest = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}

        // Create signer
        GenericSigner signer = new GenericSigner(engine, digest); // Noncompliant {{(Signature) SHA-256withRSA}}
        signer.init(true, new RSAKeyParameters(true, new BigInteger("0"), new BigInteger("1")));

        // Data to sign
        byte[] data = "Hello, World!".getBytes();

        // Perform signing
        signer.update(data, 0, data.length);
        try {
            byte[] signature = signer.generateSignature();
        } catch (DataLengthException e) {
            e.printStackTrace();
        } catch (CryptoException e) {
            e.printStackTrace();
        }
    }

    public static void test2() {

        // Initialize the AsymmetricBlockCipher engine
        AsymmetricBlockCipher engine = new PKCS1Encoding(new ElGamalEngine()); // Noncompliant {{(PublicKeyEncryption) ElGamal}} {{(PublicKeyEncryption) ElGamal}}

        // Initialize the Digest
        Digest digest = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}

        // Create signer
        GenericSigner signer = new GenericSigner(engine, digest); // Noncompliant {{(Signature) ElGamal}}
        signer.init(true, new RSAKeyParameters(true, new BigInteger("0"), new BigInteger("1")));

        // Data to sign
        byte[] data = "Hello, World!".getBytes();

        // Perform signing
        signer.update(data, 0, data.length);
        try {
            byte[] signature = signer.generateSignature();
        } catch (DataLengthException e) {
            e.printStackTrace();
        } catch (CryptoException e) {
            e.printStackTrace();
        }
    }
}
