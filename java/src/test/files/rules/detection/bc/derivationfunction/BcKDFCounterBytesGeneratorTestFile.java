import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.KDFCounterBytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KDFCounterParameters;
import org.bouncycastle.util.encoders.Hex;

public class BcKDFCounterBytesGeneratorTestFile {

    public static void main(String[] args) {
        // Define the MAC algorithm to be used (e.g., HMAC with SHA-256)
        Digest hash = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}
        Mac mac = new HMac(hash); // Noncompliant {{(Mac) HMAC-SHA-256}}

        // Input keying material (IKM) - your input key
        byte[] ikm = Hex.decode("0123456789ABCDEF0123456789ABCDEF");

        // Fixed input (optional)
        byte[] fixedInput = Hex.decode("00000000000000000000000000000000");

        // Output length (desired length of derived key)
        int length = 32; // e.g., 256 bits

        // Create the KDFCounterBytesGenerator
        KDFCounterBytesGenerator kdfGenerator =
                new KDFCounterBytesGenerator(mac); // Noncompliant {{(KeyDerivationFunction) SP800-108-CounterKDF}}

        // Initialize the generator with parameters
        kdfGenerator.init(new KDFCounterParameters(ikm, fixedInput, 128));

        // Derive the key
        byte[] derivedKey = new byte[length];
        kdfGenerator.generateBytes(derivedKey, 0, length);

        // Print the derived key
        System.out.println("Derived Key: " + Hex.toHexString(derivedKey));
    }
}
