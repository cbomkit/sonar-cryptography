import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.pqc.jcajce.provider.gmss.BCGMSSPublicKey;
import org.bouncycastle.pqc.legacy.crypto.gmss.GMSSKeyParameters;
import org.bouncycastle.pqc.legacy.crypto.gmss.GMSSParameters;
import org.bouncycastle.pqc.legacy.crypto.gmss.GMSSPublicKeyParameters;

public class BcGMSSParametersTestFile {

    public static void testGMSSKeyParameters() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES-256}}

        GMSSParameters base = new GMSSParameters(256);

        GMSSKeyParameters parameters = new GMSSKeyParameters(true, base);

        aesEngine.init(true, parameters); // true for encryption, false for decryption
    }

    public static void testGMSSPublicKeyParameters() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES-256}}

        GMSSParameters base = new GMSSParameters(256);

        GMSSPublicKeyParameters parameters = new GMSSPublicKeyParameters(new byte[12], base);

        aesEngine.init(true, parameters); // true for encryption, false for decryption
    }

    public static void testBCGMSSPublicKey1() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES-256}}

        GMSSParameters base = new GMSSParameters(256);

        BCGMSSPublicKey parameters = new BCGMSSPublicKey(new byte[12], base);

        aesEngine.init(true, parameters); // true for encryption, false for decryption
    }

    public static void testBCGMSSPublicKey2() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES-256}}

        GMSSParameters base = new GMSSParameters(256);

        GMSSPublicKeyParameters gmss = new GMSSPublicKeyParameters(new byte[12], base);

        BCGMSSPublicKey parameters = new BCGMSSPublicKey(gmss);

        aesEngine.init(true, parameters); // true for encryption, false for decryption
    }
}
