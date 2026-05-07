import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKeyTemplates;

public class TinkAeadTestFile {

    public void testAes128Gcm() throws Exception {
        AeadConfig.register();
        KeysetHandle keysetHandle =
                KeysetHandle.generateNew(AeadKeyTemplates.AES128_GCM); // Noncompliant 4
        Aead aead = keysetHandle.getPrimitive(Aead.class);
    }

    public void testAes256Gcm() throws Exception {
        AeadConfig.register();
        KeysetHandle keysetHandle =
                KeysetHandle.generateNew(AeadKeyTemplates.AES256_GCM); // Noncompliant 4
        Aead aead = keysetHandle.getPrimitive(Aead.class);
    }
}