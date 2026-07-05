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
package com.ibm.plugin.rules.detection.bc.asymmetricblockcipher;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.BooleanFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.bc.cipherparameters.BcCipherParameters;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcBufferedAsymmetricBlockCipher {

    /* Note that BufferedAsymmetricBlockCipher does *not* implement the AsymmetricBlockCipher interface */

    private BcBufferedAsymmetricBlockCipher() {
        // nothing
    }

    private static final IDetectionRule<Tree> INIT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.crypto.BufferedAsymmetricBlockCipher")
                    .forMethods("init")
                    .withMethodParameter("boolean")
                    .shouldBeDetectedAs(new BooleanFactory<>())
                    .withMethodParameter("org.bouncycastle.crypto.CipherParameters")
                    .addDependingDetectionRules(BcCipherParameters.rules())
                    .buildForContext(new CipherContext(Map.of("kind", "ENCRYPTION_STATUS")))
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CONSTRUCTOR =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.crypto.BufferedAsymmetricBlockCipher")
                    .forConstructor()
                    .shouldBeDetectedAs(new ValueActionFactory<>("BufferedAsymmetricBlockCipher"))
                    .withMethodParameter("org.bouncycastle.crypto.AsymmetricBlockCipher")
                    .addDependingDetectionRules(BcAsymmetricBlockCipher.rules())
                    .buildForContext(
                            new CipherContext(Map.of("kind", "ASYMMETRIC_BUFFERED_BLOCK_CIPHER")))
                    .inBundle(() -> "Bc")
                    .withDependingDetectionRules(List.of(INIT));

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(() -> List.of(CONSTRUCTOR));

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }
}
