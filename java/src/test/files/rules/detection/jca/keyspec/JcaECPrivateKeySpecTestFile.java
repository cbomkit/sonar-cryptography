import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

public class JcaECPrivateKeySpecTestFile {

    public static final String p = "4451685225093714772084598273548427";
    public void base() {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Noncompliant {{(BlockCipher) AES-128-ECB-PKCS5}}
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC"); // Noncompliant {{(Key) EC}}
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ecKeyPair = kpg.generateKeyPair();
        PrivateKey privateKey = ecKeyPair.getPrivate();

        ECFieldFp fieldFp = new ECFieldFp(new BigInteger(p));
        EllipticCurve curve = new EllipticCurve(fieldFp, new BigInteger("4451685225093714772084598273548424"), new BigInteger("2061118396808653202902996166388514"));
        ECPoint g = new ECPoint(new BigInteger("338530205676502674729549372677647997389429898939"), new BigInteger("842365456698940303598009444920994870805149798382"));
        ECParameterSpec spec = new ECParameterSpec(curve, g, new BigInteger("1461501637330902918203686915170869725397159163571"), 1);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey, spec);
    }

}