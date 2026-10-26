import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.BlockCipherMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class BcBlockCipherMacTestFile {

    public static void main(String[] args) {
        byte[] key = Hex.decode("00112233445566778899aabbccddeeff");
        byte[] input = "Hello, BouncyCastle!".getBytes();

        try {
            byte[] mac = calculateMac(new AESEngine(), 128, key, input); // Noncompliant {{(BlockCipher) AES}}
            System.out.println("MAC: " + Hex.toHexString(mac));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] calculateMac(
            BlockCipher cipher, int macSizeInBits, byte[] key, byte[] input) throws Exception {
        BlockCipherMac mac =
                new BlockCipherMac(cipher, macSizeInBits); // Noncompliant {{(Mac) AES}}
        CipherParameters params = new KeyParameter(key);

        mac.init(params);

        mac.update(input, 0, input.length);

        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);

        return out;
    }
}
