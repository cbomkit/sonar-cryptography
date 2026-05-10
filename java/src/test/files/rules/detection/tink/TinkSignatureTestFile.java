import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.signature.SignatureKeyTemplates;

public class TinkSignatureTestFile {

    public void testEcdsaP256() throws Exception {
        SignatureConfig.register();
        KeysetHandle keysetHandle =
                KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256); // Noncompliant 4
    }

    public void testEd25519() throws Exception {
        SignatureConfig.register();
        KeysetHandle keysetHandle =
                KeysetHandle.generateNew(SignatureKeyTemplates.ED25519); // Noncompliant 4
    }
}