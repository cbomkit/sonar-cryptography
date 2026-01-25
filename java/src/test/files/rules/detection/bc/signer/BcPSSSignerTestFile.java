import java.math.BigInteger;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;

public class BcPSSSignerTestFile {

    public static void test() {

        // Initialize the necessary parameters
        Digest contentDigest =
                new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}
        Digest mgfDigest =
                new SHA512Digest(); // Noncompliant {{(MessageDigest) SHA-512}}
        byte[] salt = new byte[20]; // Salt for the PSS padding
        byte trailer = 0x01; // Trailer field value

        // Initialize the AsymmetricBlockCipher
        AsymmetricBlockCipher cipher = new RSAEngine(); // Noncompliant {{(PublicKeyEncryption) RSA}}

        // Initialize PSSSigner
        PSSSigner signer = new PSSSigner(cipher, contentDigest, mgfDigest, salt, trailer);
        // Noncompliant@-1 {{(ProbabilisticSignatureScheme) RSA-PSS}}

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
