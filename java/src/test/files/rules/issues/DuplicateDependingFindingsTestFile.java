import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

public class DuplicateDependingFindingsTestFile {

    public byte[] encryptCEK(final RSAPublicKey pub, final SecretKey cek)
    throws RuntimeException {
        AsymmetricBlockCipher engine = new RSAEngine(); // Noncompliant {{(PublicKeyEncryption) RSA}}

        OAEPEncoding oaep = new OAEPEncoding(engine); // Noncompliant {{(PublicKeyEncryption) RSA-OAEP}}

        oaep.init(true, new RSAKeyParameters(false, null, null));

        return oaep.processBlock(cek.getEncoded(), 0, keyBytes.length);
    }
}
