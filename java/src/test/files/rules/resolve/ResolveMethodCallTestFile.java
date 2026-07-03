package test.files.rules.java.resolve;

import javax.ws.rs.BadRequestException;
import java.security.*;
import java.security.spec.*;

public class ResolveMethodCallTestFile {

    public void main(String algo) {
        try {
            KeyPair keyPair = null;
            switch (algo) {
                case "1":
                    keyPair = generateEcdsaKey("secp256r1");
                    break;
                case "2":
                    keyPair = generateEcdsaKey("secp384r1");
                    break;
                case "3":
                    keyPair = generateEcdsaKey("secp521r1");
                    break;
                default:
                    throw new RuntimeException("Unsupported signature algorithm");
            }
        } catch (Exception e) {
            throw new BadRequestException("Error generating signing keypair", e);
        }
    }

    private static KeyPair generateEcdsaKey(String ecDomainParamName) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC"); // Noncompliant {{(Key) EC}}
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(ecDomainParamName);
        keyGen.initialize(ecSpec);
        KeyPair keyPair = keyGen.generateKeyPair();
        return keyPair;
    }

}