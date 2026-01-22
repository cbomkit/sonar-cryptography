package com.ibm.plugin.rules.detection.gocrypto;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import org.sonar.plugins.go.api.Tree;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.Map;

public final class GoCryptoCipherModes {

    private GoCryptoCipherModes() {
        // nothing
    }

    // cipher.NewGCM(cipher cipher.Block) (cipher.AEAD, error)
    // Returns a new GCM mode wrapper for the given cipher block
    public static final IDetectionRule<Tree> NEW_GCM =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/cipher")
                    .forMethods("NewGCM")
                    .shouldBeDetectedAs(new ValueActionFactory<>("GCM"))
                    .withMethodParameter("cipher.Block")
                    .buildForContext(new CipherContext(Map.of("kind", "AEAD_BLOCK_CIPHER_MODE")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // cipher.NewCBCEncrypter(block cipher.Block, iv []byte) cipher.BlockMode
    // Returns a BlockMode which encrypts in cipher block chaining mode
    public static final IDetectionRule<Tree> NEW_CBC_ENCRYPTER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/cipher")
                    .forMethods("NewCBCEncrypter")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CBC"))
                    .withMethodParameter("cipher.Block")
                    .withMethodParameter("[]byte")
                    .buildForContext(new CipherContext(Map.of("kind", "BLOCK_CIPHER_MODE")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // cipher.NewCBCDecrypter(block cipher.Block, iv []byte) cipher.BlockMode
    // Returns a BlockMode which decrypts in cipher block chaining mode
    public static final IDetectionRule<Tree> NEW_CBC_DECRYPTER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/cipher")
                    .forMethods("NewCBCDecrypter")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CBC"))
                    .withMethodParameter("cipher.Block")
                    .withMethodParameter("[]byte")
                    .buildForContext(new CipherContext(Map.of("kind", "BLOCK_CIPHER_MODE")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // cipher.NewCFBEncrypter(block cipher.Block, iv []byte) cipher.Stream
    // Returns a Stream which encrypts with cipher feedback mode
    public static final IDetectionRule<Tree> NEW_CFB_ENCRYPTER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/cipher")
                    .forMethods("NewCFBEncrypter")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CFB"))
                    .withMethodParameter("cipher.Block")
                    .withMethodParameter("[]byte")
                    .buildForContext(new CipherContext(Map.of("kind", "BLOCK_CIPHER_MODE")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // cipher.NewCFBDecrypter(block cipher.Block, iv []byte) cipher.Stream
    // Returns a Stream which decrypts with cipher feedback mode
    public static final IDetectionRule<Tree> NEW_CFB_DECRYPTER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/cipher")
                    .forMethods("NewCFBDecrypter")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CFB"))
                    .withMethodParameter("cipher.Block")
                    .withMethodParameter("[]byte")
                    .buildForContext(new CipherContext(Map.of("kind", "BLOCK_CIPHER_MODE")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // cipher.NewCTR(block cipher.Block, iv []byte) cipher.Stream
    // Returns a Stream which encrypts/decrypts using counter mode
    public static final IDetectionRule<Tree> NEW_CTR =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/cipher")
                    .forMethods("NewCTR")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CTR"))
                    .withMethodParameter("cipher.Block")
                    .withMethodParameter("[]byte")
                    .buildForContext(new CipherContext(Map.of("kind", "BLOCK_CIPHER_MODE")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // cipher.NewOFB(block cipher.Block, iv []byte) cipher.Stream
    // Returns a Stream which encrypts/decrypts using output feedback mode
    public static final IDetectionRule<Tree> NEW_OFB =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/cipher")
                    .forMethods("NewOFB")
                    .shouldBeDetectedAs(new ValueActionFactory<>("OFB"))
                    .withMethodParameter("cipher.Block")
                    .withMethodParameter("[]byte")
                    .buildForContext(new CipherContext(Map.of("kind", "BLOCK_CIPHER_MODE")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(
                NEW_GCM,
                NEW_CBC_ENCRYPTER,
                NEW_CBC_DECRYPTER,
                NEW_CFB_ENCRYPTER,
                NEW_CFB_DECRYPTER,
                NEW_CTR,
                NEW_OFB);
    }
}
