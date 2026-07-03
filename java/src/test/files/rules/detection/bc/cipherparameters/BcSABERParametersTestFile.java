import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.pqc.crypto.saber.SABERKeyParameters;
import org.bouncycastle.pqc.crypto.saber.SABERParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPublicKeyParameters;

public class BcSABERParametersTestFile {

    public static void testSABERParameters() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES-512}}

        SABERParameters parameters = new SABERParameters("name", 0, 512, true, false);

        aesEngine.init(true, parameters); // true for encryption, false for decryption
    }

    public static void testSABERKeyParameters() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES-512}}

        SABERParameters base = new SABERParameters("name", 0, 512, false, false);

        SABERKeyParameters parameters = new SABERKeyParameters(false, base);

        aesEngine.init(true, parameters); // true for encryption, false for decryption
    }

    public static void testSABERPublicKeyParameters() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES-512}}

        SABERParameters base = new SABERParameters("name", 0, 512, false, false);

        SABERPublicKeyParameters parameters = new SABERPublicKeyParameters(base, new byte[12]);

        aesEngine.init(true, parameters); // true for encryption, false for decryption
    }

    public static void testSABERPrivateKeyParameters() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES-512}}

        SABERParameters base = new SABERParameters("name", 0, 512, false, false);

        SABERPrivateKeyParameters parameters = new SABERPrivateKeyParameters(base, new byte[12]);

        aesEngine.init(true, parameters); // true for encryption, false for decryption
    }
}
