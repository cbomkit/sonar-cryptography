import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.ShortenedDigest;
import org.bouncycastle.crypto.digests.NonMemoableDigest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

public class BcOAEPEncodingTestFile {

    public byte[] encryptCEK1(final RSAPublicKey pub, final SecretKey cek)
    throws RuntimeException {
        try {
            // This detection should optimally not happen once RSA has been detected as a child finding of OAEPEncoding
            AsymmetricBlockCipher engine = new RSAEngine(); // Noncompliant {{(PublicKeyEncryption) RSA}}

            // TODO: Using intermediate variables should also work
            // Digest digest = new ShortenedDigest(new SHA3Digest(), 16);
            // Digest digest = new SHA3Digest();
            OAEPEncoding cipher = new OAEPEncoding(engine, new ShortenedDigest(new SHA3Digest(), 16)); // Noncompliant  {{(MessageDigest) SHA-3}} {{(PublicKeyEncryption) RSA-OAEP}}

            BigInteger mod = pub.getModulus();
            BigInteger exp = pub.getPublicExponent();
            RSAKeyParameters keyParams = new RSAKeyParameters(false, mod, exp);
            cipher.init(true, keyParams);

            // int inputBlockSize = cipher.getInputBlockSize();
            // int outputBlockSize = cipher.getOutputBlockSize();

            byte[] keyBytes = cek.getEncoded();

            return cipher.processBlock(keyBytes, 0, keyBytes.length);

        } catch (Exception e) {
            // org.bouncycastle.crypto.InvalidCipherTextException
            throw new RuntimeException(e);
        }
    }

    public byte[] encryptCEK2(final RSAPublicKey pub, final SecretKey cek)
    throws RuntimeException {
        try {
            // This detection should optimally not happen once RSA has been detected as a child finding of OAEPEncoding
            AsymmetricBlockCipher engine = new RSAEngine(); // Noncompliant {{(PublicKeyEncryption) RSA}}

            OAEPEncoding cipher = new OAEPEncoding(engine, new NonMemoableDigest(new SHA3Digest()), new SHA512Digest(), new byte[16]); // Noncompliant {{(MessageDigest) SHA-3}} {{(MessageDigest) SHA-3}} {{(MessageDigest) SHA-512}} {{(PublicKeyEncryption) RSA-OAEP}}

            BigInteger mod = pub.getModulus();
            BigInteger exp = pub.getPublicExponent();
            RSAKeyParameters keyParams = new RSAKeyParameters(false, mod, exp);
            cipher.init(true, keyParams);

            byte[] keyBytes = cek.getEncoded();

            return cipher.processBlock(keyBytes, 0, keyBytes.length);

        } catch (Exception e) {
            // org.bouncycastle.crypto.InvalidCipherTextException
            throw new RuntimeException(e);
        }
    }
}
