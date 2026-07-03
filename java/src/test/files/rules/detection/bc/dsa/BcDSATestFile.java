import java.math.BigInteger;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;

public class BcDSATestFile {
    public static void main(String[] args) throws CryptoException {
        // Define curve parameters (e.g., secp256r1)
        ECDomainParameters curveParams = new ECDomainParameters(null);

        // Generate key pair
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keyGenParams =
                new ECKeyGenerationParameters(curveParams, null);
        keyPairGenerator.init(keyGenParams);
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Extract private key
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();

        // Sign a message
        byte[] message = "Hello, ECDSA!".getBytes();
        ECDSASigner signer = new ECDSASigner(); // Noncompliant {{(Signature) ECDSA}}
        signer.init(true, privateKey); // true for signing
        BigInteger[] signature = signer.generateSignature(message);
    }
}
