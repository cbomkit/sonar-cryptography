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
import org.sonar.plugins.go.api.Tree;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.Map;

/**
 * Detection rules for Go's crypto/aes package.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>aes.NewCipher(key) - creates a new AES cipher block
 *   <li>cipher.NewGCM(block) - creates a GCM mode cipher (depending rule)
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
                    .buildForContext(
                            new CipherContext(Map.of("kind", "AEAD_BLOCK_CIPHER_MODE")))
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
                    .withDependingDetectionRules(List.of(NEW_GCM));

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(NEW_CIPHER);
    }
}
