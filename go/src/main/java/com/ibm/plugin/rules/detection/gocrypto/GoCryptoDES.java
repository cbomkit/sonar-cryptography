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

import static com.ibm.plugin.rules.detection.gocrypto.GoCryptoCipherModes.NEW_CBC_DECRYPTER;
import static com.ibm.plugin.rules.detection.gocrypto.GoCryptoCipherModes.NEW_CBC_ENCRYPTER;
import static com.ibm.plugin.rules.detection.gocrypto.GoCryptoCipherModes.NEW_CFB_DECRYPTER;
import static com.ibm.plugin.rules.detection.gocrypto.GoCryptoCipherModes.NEW_CFB_ENCRYPTER;
import static com.ibm.plugin.rules.detection.gocrypto.GoCryptoCipherModes.NEW_CTR;
import static com.ibm.plugin.rules.detection.gocrypto.GoCryptoCipherModes.NEW_OFB;

/**
 * Detection rules for Go's crypto/des package.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>des.NewCipher(key) - creates a new DES cipher (weak, 56-bit key)
 *   <li>des.NewTripleDESCipher(key) - creates a new 3DES cipher
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class GoCryptoDES {

    private GoCryptoDES() {
        // private
    }

    // des.NewCipher(key []byte) (cipher.Block, error)
    // Creates and returns a new DES cipher.Block
    private static final IDetectionRule<Tree> NEW_CIPHER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/des")
                    .forMethods("NewCipher")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DES"))
                    .withMethodParameter("[]byte")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "GoCrypto")
                    .withDependingDetectionRules(
                            List.of(
                                    NEW_CBC_ENCRYPTER,
                                    NEW_CBC_DECRYPTER,
                                    NEW_CFB_ENCRYPTER,
                                    NEW_CFB_DECRYPTER,
                                    NEW_CTR,
                                    NEW_OFB));

    // des.NewTripleDESCipher(key []byte) (cipher.Block, error)
    // Creates and returns a new Triple DES cipher.Block
    private static final IDetectionRule<Tree> NEW_TRIPLE_DES_CIPHER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/des")
                    .forMethods("NewTripleDESCipher")
                    .shouldBeDetectedAs(new ValueActionFactory<>("3DES"))
                    .withMethodParameter("[]byte")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "GoCrypto")
                    .withDependingDetectionRules(
                            List.of(
                                    NEW_CBC_ENCRYPTER,
                                    NEW_CBC_DECRYPTER,
                                    NEW_CFB_ENCRYPTER,
                                    NEW_CFB_DECRYPTER,
                                    NEW_CTR,
                                    NEW_OFB));

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(NEW_CIPHER, NEW_TRIPLE_DES_CIPHER);
    }
}
