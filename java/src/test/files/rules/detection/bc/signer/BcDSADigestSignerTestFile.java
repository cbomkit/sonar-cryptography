import java.math.BigInteger;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;

public class BcDSADigestSignerTestFile {

    public static void test() {

        // Initialize the Digest
        Digest digest = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}

        // Initialize DSASginer
        DSASigner dsa = new DSASigner(); // Noncompliant {{(Signature) DSA}}

        // Initialize DSADigestSigner
        DSADigestSigner signer =
                new DSADigestSigner(dsa, digest, new StandardDSAEncoding());
        // Noncompliant@-1 {{(Signature) SHA-256withDSA}}

        signer.init(true, new RSAKeyParameters(true, new BigInteger("0"), new BigInteger("1")));

        // Data to sign
        byte[] data = "Hello, World!".getBytes();

        // Perform signing
        signer.update(data, 0, data.length);
        byte[] signature = signer.generateSignature();
    }
}
