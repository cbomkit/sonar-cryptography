/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

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
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // cipher.NewGCMWithNonceSize(cipher cipher.Block, size int) (cipher.AEAD, error)
    // Returns a new GCM mode wrapper with a custom nonce size
    public static final IDetectionRule<Tree> NEW_GCM_WITH_NONCE_SIZE =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/cipher")
                    .forMethods("NewGCMWithNonceSize")
                    .shouldBeDetectedAs(new ValueActionFactory<>("GCM"))
                    .withMethodParameter("cipher.Block")
                    .withMethodParameter("int")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // cipher.NewGCMWithRandomNonce(cipher cipher.Block) (cipher.AEAD, error)
    // Returns a new GCM mode wrapper that generates random nonces (Go 1.25+)
    public static final IDetectionRule<Tree> NEW_GCM_WITH_RANDOM_NONCE =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/cipher")
                    .forMethods("NewGCMWithRandomNonce")
                    .shouldBeDetectedAs(new ValueActionFactory<>("GCM"))
                    .withMethodParameter("cipher.Block")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // cipher.NewGCMWithTagSize(cipher cipher.Block, tagSize int) (cipher.AEAD, error)
    // Returns a new GCM mode wrapper with a custom tag size
    public static final IDetectionRule<Tree> NEW_GCM_WITH_TAG_SIZE =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/cipher")
                    .forMethods("NewGCMWithTagSize")
                    .shouldBeDetectedAs(new ValueActionFactory<>("GCM"))
                    .withMethodParameter("cipher.Block")
                    .withMethodParameter("int")
                    .buildForContext(new CipherContext())
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
                    .buildForContext(new CipherContext())
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
                    .buildForContext(new CipherContext())
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
                    .buildForContext(new CipherContext())
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
                    .buildForContext(new CipherContext())
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
                    .buildForContext(new CipherContext())
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
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(
                NEW_GCM,
                NEW_GCM_WITH_NONCE_SIZE,
                NEW_GCM_WITH_RANDOM_NONCE,
                NEW_GCM_WITH_TAG_SIZE,
                NEW_CBC_ENCRYPTER,
                NEW_CBC_DECRYPTER,
                NEW_CFB_ENCRYPTER,
                NEW_CFB_DECRYPTER,
                NEW_CTR,
                NEW_OFB);
    }
}
