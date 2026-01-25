import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class BcOpenSSLPBEParametersGeneratorTestFile {
    public static void test1() {
        // Input password and salt (random bytes)
        String password = "MySecretPassword";
        byte[] salt = Hex.decode("e04fd020ea3a6910a2d808002b30309d");

        // Desired output key length
        int keyLength = 128; // in bits

        // Create the OpenSSLPBEParametersGenerator
        OpenSSLPBEParametersGenerator generator =
                new OpenSSLPBEParametersGenerator(); // Noncompliant {{(PasswordBasedEncryption) PBES1}}

        // Initialize the generator with password and salt
        generator.init(password.getBytes(), salt, 1000); // 1000 is the iteration count

        // Generate the key parameters
        KeyParameter keyParameter = (KeyParameter) generator.generateDerivedParameters(keyLength);

        // Get the derived key bytes
        byte[] derivedKey = keyParameter.getKey();

        // Print the derived key in hexadecimal format
        System.out.println("Derived Key: " + Hex.toHexString(derivedKey));
    }

    public static void test2() {
        // Input password and salt (random bytes)
        String password = "MySecretPassword";
        byte[] salt = Hex.decode("e04fd020ea3a6910a2d808002b30309d");

        // Desired output key length
        int keyLength = 128; // in bits

        // Create a digest (SHA-256 in this example)
        SHA256Digest sha256Digest = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}

        // Create the OpenSSLPBEParametersGenerator with the digest
        OpenSSLPBEParametersGenerator generator =
                new OpenSSLPBEParametersGenerator(sha256Digest); // Noncompliant {{(PasswordBasedEncryption) PBES1}}

        // Initialize the generator with password and salt
        generator.init(password.getBytes(), salt, 1000); // 1000 is the iteration count

        // Generate the key parameters
        KeyParameter keyParameter = (KeyParameter) generator.generateDerivedParameters(keyLength);

        // Get the derived key bytes
        byte[] derivedKey = keyParameter.getKey();

        // Print the derived key in hexadecimal format
        System.out.println("Derived Key: " + Hex.toHexString(derivedKey));
    }
}
