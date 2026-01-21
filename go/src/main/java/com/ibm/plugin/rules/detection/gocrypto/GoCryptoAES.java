/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ibm.plugin.rules.detection.gocrypto;

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

/**
 * Detection rules for Go's crypto/aes package.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>aes.NewCipher(key) - creates a new AES cipher block
 *   <li>cipher.NewGCM(block) - creates a GCM mode cipher (depending rule)
 *   <li>cipher.NewCBCEncrypter(block, iv) - creates a CBC encrypter (depending rule)
 *   <li>cipher.NewCBCDecrypter(block, iv) - creates a CBC decrypter (depending rule)
 *   <li>cipher.NewCFBEncrypter(block, iv) - creates a CFB encrypter (depending rule)
 *   <li>cipher.NewCFBDecrypter(block, iv) - creates a CFB decrypter (depending rule)
 *   <li>cipher.NewCTR(block, iv) - creates a CTR stream cipher (depending rule)
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class GoCryptoAES {

    private GoCryptoAES() {
        // private
    }

    // cipher.NewGCM(cipher cipher.Block) (cipher.AEAD, error)
    // Returns a new GCM mode wrapper for the given cipher block
    private static final IDetectionRule<Tree> NEW_GCM =
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
    private static final IDetectionRule<Tree> NEW_CBC_ENCRYPTER =
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
    private static final IDetectionRule<Tree> NEW_CBC_DECRYPTER =
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
    private static final IDetectionRule<Tree> NEW_CFB_ENCRYPTER =
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
    private static final IDetectionRule<Tree> NEW_CFB_DECRYPTER =
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
    private static final IDetectionRule<Tree> NEW_CTR =
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

    // aes.NewCipher(key []byte) (cipher.Block, error)
    // The key argument should be the AES key, either 16, 24, or 32 bytes
    // to select AES-128, AES-192, or AES-256.
    private static final IDetectionRule<Tree> NEW_CIPHER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/aes")
                    .forMethods("NewCipher")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES"))
                    .withMethodParameter("[]byte")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "GoCrypto")
                    .withDependingDetectionRules(
                            List.of(
                                    NEW_GCM,
                                    NEW_CBC_ENCRYPTER,
                                    NEW_CBC_DECRYPTER,
                                    NEW_CFB_ENCRYPTER,
                                    NEW_CFB_DECRYPTER,
                                    NEW_CTR));

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(NEW_CIPHER);
    }
}
