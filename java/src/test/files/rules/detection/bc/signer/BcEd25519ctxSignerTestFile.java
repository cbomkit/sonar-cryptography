import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519ctxSigner;

public class BcEd25519ctxSignerTestFile {

    public static void test() {
        // Create signer with a context
        byte[] context = "Example Context".getBytes();
        Ed25519ctxSigner signer = new Ed25519ctxSigner(context); // Noncompliant {{(Signature) Ed25519}}
        signer.init(true, new Ed25519PrivateKeyParameters(null));

        // Data to sign
        byte[] data = "Hello, World!".getBytes();

        // Perform signing
        signer.update(data, 0, data.length);
        byte[] signature = signer.generateSignature();
    }
}
