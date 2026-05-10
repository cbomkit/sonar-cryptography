import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.mac.MacKeyTemplates;

public class TinkMacTestFile {

    public void testHmacSha256() throws Exception {
        MacConfig.register();
        KeysetHandle keysetHandle =
                KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA256_128BITTAG); // Noncompliant 4
    }

    public void testHmacSha512() throws Exception {
        MacConfig.register();
        KeysetHandle keysetHandle =
                KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA512_256BITTAG); // Noncompliant 4
    }
}