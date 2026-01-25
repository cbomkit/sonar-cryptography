import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.util.encoders.Hex;

public class BcHKDFBytesGeneratorTestFile {

    public static void test1() {
        // Define the digest algorithm to be used (e.g., SHA-256)
        Digest hash = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}

        // Input keying material (IKM) - your input key
        byte[] ikm = Hex.decode("0123456789ABCDEF0123456789ABCDEF");

        // Salt value (optional)
        byte[] salt = Hex.decode("00000000000000000000000000000000");

        // Info value (optional)
        byte[] info = Hex.decode("f0f1f2f3f4f5f6f7f8f9");

        // Output length (desired length of derived key)
        int length = 32; // e.g., 256 bits

        // Create the HKDFBytesGenerator
        HKDFBytesGenerator hkdfGenerator =
                new HKDFBytesGenerator(hash); // Noncompliant {{(KeyDerivationFunction) HKDF-SHA-256}}

        // Initialize the generator with parameters
        hkdfGenerator.init(new HKDFParameters(ikm, salt, info));

        // Derive the key
        byte[] derivedKey = new byte[length];
        hkdfGenerator.generateBytes(derivedKey, 0, length);

        // Print the derived key
        System.out.println("Derived Key: " + Hex.toHexString(derivedKey));
    }

    // Test where the digest constructor is written directly as an argument of HKDFBytesGenerator,
    // without an intermediary variable.
    public static void test2() {
        // Input keying material (IKM) - your input key
        byte[] ikm = Hex.decode("0123456789ABCDEF0123456789ABCDEF");

        // Salt value (optional)
        byte[] salt = Hex.decode("00000000000000000000000000000000");

        // Info value (optional)
        byte[] info = Hex.decode("f0f1f2f3f4f5f6f7f8f9");

        // Output length (desired length of derived key)
        int length = 32; // e.g., 256 bits

        // Create the HKDFBytesGenerator
        HKDFBytesGenerator hkdfGenerator =
                new HKDFBytesGenerator(new SHA512Digest()); // Noncompliant {{(KeyDerivationFunction) HKDF-SHA-512}} {{(MessageDigest) SHA-512}}

        // Initialize the generator with parameters
        hkdfGenerator.init(new HKDFParameters(ikm, salt, info));

        // Derive the key
        byte[] derivedKey = new byte[length];
        hkdfGenerator.generateBytes(derivedKey, 0, length);

        // Print the derived key
        System.out.println("Derived Key: " + Hex.toHexString(derivedKey));
    }
}