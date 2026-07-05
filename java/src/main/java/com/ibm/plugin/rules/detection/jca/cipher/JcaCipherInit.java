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
package com.ibm.plugin.rules.detection.jca.cipher;

import static com.ibm.plugin.rules.detection.TypeShortcuts.CIPHER_TYPE;
import static com.ibm.plugin.rules.detection.TypeShortcuts.KEY_TYPE;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.OperationModeFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.jca.algorithmspec.JcaAlgorithmParameterSpec;
import com.ibm.plugin.rules.detection.jca.keyspec.JcaKeySpec;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JcaCipherInit {

    private static final IDetectionRule<Tree> CIPHER_INIT_1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(CIPHER_TYPE)
                    .forMethods("init")
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new OperationModeFactory<>())
                    .withMethodParameter("java.security.cert.Certificate")
                    .buildForContext(new CipherContext(Map.of("kind", "PKE")))
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CIPHER_INIT_2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(CIPHER_TYPE)
                    .forMethods("init")
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new OperationModeFactory<>())
                    .withMethodParameter("java.security.cert.Certificate")
                    .withMethodParameter("java.security.SecureRandom")
                    .buildForContext(new CipherContext(Map.of("kind", "PKE")))
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CIPHER_INIT_3 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(CIPHER_TYPE)
                    .forMethods("init")
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new OperationModeFactory<>())
                    .withMethodParameter(KEY_TYPE)
                    .addDependingDetectionRules(JcaKeySpec.rules())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CIPHER_INIT_4 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(CIPHER_TYPE)
                    .forMethods("init")
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new OperationModeFactory<>())
                    .withMethodParameter(KEY_TYPE)
                    .addDependingDetectionRules(JcaKeySpec.rules())
                    .withMethodParameter("java.security.AlgorithmParameters")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CIPHER_INIT_5 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(CIPHER_TYPE)
                    .forMethods("init")
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new OperationModeFactory<>())
                    .withMethodParameter(KEY_TYPE)
                    .addDependingDetectionRules(JcaKeySpec.rules())
                    .withMethodParameter("java.security.spec.AlgorithmParameterSpec")
                    .addDependingDetectionRules(JcaAlgorithmParameterSpec.rules())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CIPHER_INIT_6 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(CIPHER_TYPE)
                    .forMethods("init")
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new OperationModeFactory<>())
                    .withMethodParameter(KEY_TYPE)
                    .addDependingDetectionRules(JcaKeySpec.rules())
                    .withMethodParameter("java.security.AlgorithmParameters")
                    .withMethodParameter("java.security.SecureRandom")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CIPHER_INIT_7 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(CIPHER_TYPE)
                    .forMethods("init")
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new OperationModeFactory<>())
                    .withMethodParameter(KEY_TYPE)
                    .addDependingDetectionRules(JcaKeySpec.rules())
                    .withMethodParameter("java.security.spec.AlgorithmParameterSpec")
                    .addDependingDetectionRules(JcaAlgorithmParameterSpec.rules())
                    .withMethodParameter("java.security.SecureRandom")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CIPHER_INIT_8 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(CIPHER_TYPE)
                    .forMethods("init")
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new OperationModeFactory<>())
                    .withMethodParameter(KEY_TYPE)
                    .addDependingDetectionRules(JcaKeySpec.rules())
                    .withMethodParameter("java.security.SecureRandom")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private JcaCipherInit() {
        // nothing
    }

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(JcaCipherInit::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(
                CIPHER_INIT_1,
                CIPHER_INIT_2,
                CIPHER_INIT_3,
                CIPHER_INIT_4,
                CIPHER_INIT_5,
                CIPHER_INIT_6,
                CIPHER_INIT_7,
                CIPHER_INIT_8);
    }
}
