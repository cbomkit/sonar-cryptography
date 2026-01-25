import java.math.BigInteger;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.pqc.crypto.DigestingMessageSigner;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCS256Signer;

public class BcDigestingMessageSignerTestFile {

    public static void test() {

        // Initialize the Digest
        Digest digest = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}

        // Create SPHINCS signer with SHAKEDigest
        SPHINCS256Signer sphincsSigner =
                new SPHINCS256Signer(new SHAKEDigest(128), new SHAKEDigest(256));
        // Noncompliant@-1 {{(ExtendableOutputFunction) SHAKE128}} {{(ExtendableOutputFunction) SHAKE256}}

        // Initialize DigestingMessageSigner with SPHINCS signer and SHAKEDigest
        DigestingMessageSigner signer = new DigestingMessageSigner(sphincsSigner, digest);
        // Noncompliant@-1 {{(Signature) SPHINCS-256}}

        signer.init(true, new RSAKeyParameters(true, new BigInteger("0"), new BigInteger("1")));

        // Data to sign
        byte[] data = "Hello, World!".getBytes();

        // Perform signing
        signer.update(data, 0, data.length);
        byte[] signature = signer.generateSignature();
    }
}
