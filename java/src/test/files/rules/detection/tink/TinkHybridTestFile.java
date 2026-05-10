import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.crypto.tink.hybrid.HybridKeyTemplates;

public class TinkHybridTestFile {

    public void testEciesP256() throws Exception {
        HybridConfig.register();
        KeysetHandle keysetHandle = KeysetHandle.generateNew(HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM); // Noncompliant 4
    }

    public void testEciesP256Ctr() throws Exception {
        HybridConfig.register();
        KeysetHandle keysetHandle = KeysetHandle.generateNew(HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256); // Noncompliant 4
    }
}
