package test.files.rules.java.resolve;

import java.io.File;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;

public class ResolveFunctionCascadeTestFile {

    public Cipher getCipher2(String type2) throws InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        return Cipher.getInstance(type2);
    }

    public Cipher getCipher1(String type1)  throws InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        return getCipher2(type1);
    }

    public Cipher getCipher(String type)  throws InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        Cipher c1 = getCipher1(type);
        return c1;
    }

    public void startCipherCascade() throws InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        Cipher c = getCipher("AES/ECB/NoPadding");  // Noncompliant {{(BlockCipher) AES-128-ECB}}
    }

}