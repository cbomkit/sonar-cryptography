import java.math.BigInteger;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.CramerShoupParameters;
import org.bouncycastle.crypto.params.CramerShoupPrivateKeyParameters;
import org.bouncycastle.crypto.params.CramerShoupPublicKeyParameters;

public class BcCramerShoupParametersTestFile {

    public static void testCramerShoupParameters() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES}}

        Digest digest = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}
        CramerShoupParameters parameters =
                new CramerShoupParameters(
                        new BigInteger("1"), new BigInteger("1"), new BigInteger("1"), digest);

        aesEngine.init(true, parameters); // true for encryption, false for decryption
    }

    public static void testCramerShoupPrivateKeyParameters() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES}}

        Digest digest = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}
        CramerShoupParameters base =
                new CramerShoupParameters(
                        new BigInteger("1"), new BigInteger("1"), new BigInteger("1"), digest);

        CramerShoupPrivateKeyParameters parameters =
                new CramerShoupPrivateKeyParameters(
                        base,
                        new BigInteger("1"),
                        new BigInteger("1"),
                        new BigInteger("1"),
                        new BigInteger("1"),
                        new BigInteger("1"));

        aesEngine.init(true, parameters); // true for encryption, false for decryption
    }

    public static void testCramerShoupPublicKeyParameters() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES}}

        Digest digest = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}
        CramerShoupParameters base =
                new CramerShoupParameters(
                        new BigInteger("1"), new BigInteger("1"), new BigInteger("1"), digest);

        CramerShoupPublicKeyParameters parameters =
                new CramerShoupPublicKeyParameters(
                        base, new BigInteger("1"), new BigInteger("1"), new BigInteger("1"));

        aesEngine.init(true, parameters); // true for encryption, false for decryption
    }
}
