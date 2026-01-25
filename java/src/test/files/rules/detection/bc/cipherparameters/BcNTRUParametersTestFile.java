import java.io.IOException;
import java.util.List;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.pqc.legacy.crypto.ntru.NTRUEncryptionKeyParameters;
import org.bouncycastle.pqc.legacy.crypto.ntru.NTRUEncryptionParameters;
import org.bouncycastle.pqc.legacy.crypto.ntru.NTRUEncryptionPrivateKeyParameters;
import org.bouncycastle.pqc.legacy.crypto.ntru.NTRUEncryptionPublicKeyParameters;
import org.bouncycastle.pqc.legacy.crypto.ntru.NTRUSigningKeyGenerationParameters;
import org.bouncycastle.pqc.legacy.crypto.ntru.NTRUSigningParameters;
import org.bouncycastle.pqc.legacy.crypto.ntru.NTRUSigningPrivateKeyParameters;
import org.bouncycastle.pqc.legacy.crypto.ntru.NTRUSigningPublicKeyParameters;

public class BcNTRUParametersTestFile {

    public static void testNTRUEncryptionKeyParameters() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES}}

        Digest digest = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}
        NTRUEncryptionParameters base =
                new NTRUEncryptionParameters(
                        0, 0, 0, 0, 0, 0, 0, 0, false, new byte[12], false, true, digest);

        NTRUEncryptionKeyParameters parameters = new NTRUEncryptionKeyParameters(false, base);

        aesEngine.init(true, parameters); // true for encryption, false for decryption
    }

    public static void testNTRUEncryptionPublicKeyParameters() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES}}

        Digest digest = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}
        NTRUEncryptionParameters base =
                new NTRUEncryptionParameters(
                        0, 0, 0, 0, 0, 0, 0, 0, false, new byte[12], false, true, digest);

        NTRUEncryptionPublicKeyParameters parameters =
                new NTRUEncryptionPublicKeyParameters(new byte[12], base);

        aesEngine.init(true, parameters); // true for encryption, false for decryption
    }

    public static void testNTRUEncryptionPrivateKeyParameters() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES}}

        Digest digest = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}
        NTRUEncryptionParameters base =
                new NTRUEncryptionParameters(
                        0, 0, 0, 0, 0, 0, 0, 0, false, new byte[12], false, true, digest);

        try {
            NTRUEncryptionPrivateKeyParameters parameters =
                    new NTRUEncryptionPrivateKeyParameters(new byte[12], base);

            aesEngine.init(true, parameters); // true for encryption, false for decryption
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void testNTRUSigningPrivateKeyParameters1() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES}}

        Digest digest = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}
        NTRUSigningKeyGenerationParameters base =
                new NTRUSigningKeyGenerationParameters(
                        0, 0, 0, 0, 0, 1.0d, 1.0d, 1.0d, false, false, 0, digest);

        NTRUSigningPrivateKeyParameters parameters;
        try {
            parameters = new NTRUSigningPrivateKeyParameters(new byte[12], base);

            aesEngine.init(true, parameters); // true for encryption, false for decryption
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void testNTRUSigningPrivateKeyParameters2() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES}}

        Digest digest = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}
        NTRUSigningParameters base = new NTRUSigningParameters(0, 0, 0, 0, 1.0d, 1.0d, digest);

        NTRUSigningPublicKeyParameters publicKey =
                new NTRUSigningPublicKeyParameters(new byte[12], base);

        List<NTRUSigningPrivateKeyParameters.Basis> bases = List.of();

        NTRUSigningPrivateKeyParameters parameters =
                new NTRUSigningPrivateKeyParameters(bases, publicKey);

        aesEngine.init(true, parameters); // true for encryption, false for decryption
    }

    public static void testNTRUSigningPublicKeyParameters() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES}}

        Digest digest = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}
        NTRUSigningParameters base = new NTRUSigningParameters(0, 0, 0, 0, 1.0d, 1.0d, digest);

        NTRUSigningPublicKeyParameters parameters =
                new NTRUSigningPublicKeyParameters(new byte[12], base);

        aesEngine.init(true, parameters); // true for encryption, false for decryption
    }
}
