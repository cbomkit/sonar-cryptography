import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.IESParameters;
import org.bouncycastle.crypto.params.IESWithCipherParameters;

public class BcIESParametersTestFile {

    public static void testIESParameters() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES}}

        IESParameters parameters = new IESParameters(new byte[12], new byte[12], 256);

        aesEngine.init(true, parameters); // true for encryption, false for decryption
    }

    public static void testIESWithCipherParameters() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES-128}}

        IESWithCipherParameters parameters =
                new IESWithCipherParameters(new byte[12], new byte[12], 256, 128);

        aesEngine.init(true, parameters); // true for encryption, false for decryption
    }
}
