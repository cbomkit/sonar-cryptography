import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcKeyParametersTestFile {

    public static void testKeyParameter() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES-128}}

        KeyParameter parameters = new KeyParameter(new byte[12], 0, 128);

        aesEngine.init(true, parameters); // true for encryption, false for decryption
    }
}
