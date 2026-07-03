import java.math.BigInteger;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.RSADigestSigner;

public class Issue297RsaTestFile {

    void test() {
        int keySizeBits = 2048;
        int strength = 1024;

        BigInteger publicExponent = BigInteger.valueOf(0x10001);
        RSAKeyGenerationParameters p = new RSAKeyGenerationParameters(publicExponent, null, keySizeBits, strength);

        RSAKeyPairGenerator g = new RSAKeyPairGenerator(); // Noncompliant {{(PublicKeyEncryption) RSA-2048}}
        g.init(p);

        AsymmetricCipherKeyPair kp = g.generateKeyPair();
        RSAPrivateCrtKeyParameters pri = (RSAPrivateCrtKeyParameters)kp.getPrivate();
        RSAKeyParameters pub = (RSAKeyParameters)kp.getPublic();
    }

}