import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

public class DuplicateParameterFindingsTestFile {

    public byte[] encryptCEK(final RSAPublicKey pub, final SecretKey cek)
    throws RuntimeException {
        AsymmetricBlockCipher engine = new RSAEngine(); // Noncompliant {{(PublicKeyEncryption) RSA}}
        OAEPEncoding cipher = new OAEPEncoding(engine, new SHA3Digest(), new SHA512Digest(), new byte[16]); // Noncompliant {{(MessageDigest) SHA-3}} {{(MessageDigest) SHA-512}} {{(PublicKeyEncryption) RSA-OAEP}}
        return cipher.processBlock(cek.getEncoded(), 0, keyBytes.length);
    }
}
