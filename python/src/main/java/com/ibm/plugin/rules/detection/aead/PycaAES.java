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
package com.ibm.plugin.rules.detection.aead;

import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.engine.model.factory.CipherActionFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class PycaAES {

    private PycaAES() {
        // private
    }

    private static final List<String> aesAlgorithms =
            Arrays.asList("AESGCM", "AESGCMIV", "AESOCB3", "AESSIV", "AESCCM");

    private static final String AEAD_TYPE_PREFIX = "cryptography.hazmat.primitives.ciphers.aead.";

    private static @Nonnull IDetectionRule<Tree> encryptAES(String aesAlgorithm) {
        return new DetectionRuleBuilder<Tree>()
                .createDetectionRule()
                .forObjectTypes(AEAD_TYPE_PREFIX + aesAlgorithm)
                .forMethods("encrypt")
                .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                .withAnyParameters()
                .buildForContext(
                        new CipherContext(Map.of("algorithm", aesAlgorithm, "kind", "AEAD")))
                .inBundle(() -> "Pyca")
                .withoutDependingDetectionRules();
    }

    private static @Nonnull IDetectionRule<Tree> decryptAES(String aesAlgorithm) {
        return new DetectionRuleBuilder<Tree>()
                .createDetectionRule()
                .forObjectTypes(AEAD_TYPE_PREFIX + aesAlgorithm)
                .forMethods("decrypt")
                .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                .withAnyParameters()
                .buildForContext(
                        new CipherContext(Map.of("algorithm", aesAlgorithm, "kind", "AEAD")))
                .inBundle(() -> "Pyca")
                .withoutDependingDetectionRules();
    }

    private static @Nonnull List<IDetectionRule<Tree>> generationRulesAES() {
        LinkedList<IDetectionRule<Tree>> rules = new LinkedList<>();
        for (String aesAlgorithm : aesAlgorithms) {
            rules.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes(AEAD_TYPE_PREFIX + aesAlgorithm)
                            .forMethods("generate_key")
                            .withMethodParameter("int")
                            .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                            .buildForContext(
                                    new SecretKeyContext(
                                            Map.of("algorithm", aesAlgorithm, "kind", "AEAD")))
                            .inBundle(() -> "Pyca")
                            .withDependingDetectionRules(
                                    List.of(decryptAES(aesAlgorithm), encryptAES(aesAlgorithm))));
        }
        return rules;
    }

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(PycaAES::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return generationRulesAES();
    }
}
