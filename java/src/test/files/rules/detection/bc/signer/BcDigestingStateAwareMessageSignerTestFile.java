import java.math.BigInteger;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.pqc.crypto.DigestingStateAwareMessageSigner;
import org.bouncycastle.pqc.legacy.crypto.gmss.GMSSStateAwareSigner;

public class BcDigestingStateAwareMessageSignerTestFile {

    public static void test() {

        // Initialize the Digest
        Digest digest = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}

        // Create SPHINCS signer with SHAKEDigest
        GMSSStateAwareSigner gmssSigner = new GMSSStateAwareSigner(new SHAKEDigest(256)); // Noncompliant {{(ExtendableOutputFunction) SHAKE256}}

        // Initialize DigestingStateAwareMessageSigner with SPHINCS signer and SHAKEDigest
        DigestingStateAwareMessageSigner signer = new DigestingStateAwareMessageSigner(gmssSigner, digest);
        // Noncompliant@-1 {{(Signature) GMSS}}

        signer.init(true, new RSAKeyParameters(true, new BigInteger("0"), new BigInteger("1")));

        // Data to sign
        byte[] data = "Hello, World!".getBytes();

        // Perform signing
        signer.update(data, 0, data.length);
        byte[] signature = signer.generateSignature();
    }
}
