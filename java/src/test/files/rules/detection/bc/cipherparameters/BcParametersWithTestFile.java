import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.pqc.legacy.crypto.gmss.GMSSKeyParameters;
import org.bouncycastle.pqc.legacy.crypto.gmss.GMSSParameters;

public class BcParametersWithTestFile {

    public static void testParametersWithID() {
        // Create a block cipher engine
        BlockCipher aesEngine = AESEngine.newInstance(); // Noncompliant {{(BlockCipher) AES-256}}

        GMSSParameters base = new GMSSParameters(256);

        GMSSKeyParameters parameters = new GMSSKeyParameters(true, base);

        ParametersWithID parametersWithID = new ParametersWithID(parameters, new byte[12]);

        aesEngine.init(true, parametersWithID); // true for encryption, false for decryption
    }
}
