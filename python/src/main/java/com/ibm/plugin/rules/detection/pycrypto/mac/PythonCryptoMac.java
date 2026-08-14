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
package com.ibm.plugin.rules.detection.pycrypto.mac;

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class PythonCryptoMac {

    private PythonCryptoMac() {
        // private
    }

    private static final IDetectionRule<Tree> CMAC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Hash.CMAC", "Cryptodome.Hash.CMAC")
                    .forMethods("new")
                    .withMethodParameter(ANY) // key
                    .withMethodParameter(ANY) // Crypto.Cipher.* or Cryptodome.Cipher.*
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new MacContext(Map.of("kind", "cmac")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CMAC_MSG =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Hash.CMAC", "Cryptodome.Hash.CMAC")
                    .forMethods("new")
                    .withMethodParameter(ANY) // key
                    .withMethodParameter(ANY) // msg
                    .withMethodParameter(ANY) // Crypto.Cipher.* or Cryptodome.Cipher.*
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withOtherParameters()
                    .buildForContext(new MacContext(Map.of("kind", "cmac")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> HMAC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Hash.HMAC", "Cryptodome.Hash.HMAC")
                    .forMethods("new")
                    .withMethodParameter(ANY) // secret
                    .withMethodParameter(ANY) // Crypto.Hash.* or Cryptodome.Hash.*
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new MacContext(Map.of("kind", "hmac")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> HMAC_MSG =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Hash.HMAC", "Cryptodome.Hash.HMAC")
                    .forMethods("new")
                    .withMethodParameter(ANY) // secret
                    .withMethodParameter(ANY) // message
                    .withMethodParameter(ANY) // Crypto.Hash.* or Cryptodome.Hash.*
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new MacContext(Map.of("kind", "hmac")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    public static final List<String> simpleMACs = List.of("KMAC128", "KMAC256", "Poly1305");

    @Nonnull
    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(PythonCryptoMac::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        List<IDetectionRule<Tree>> rules = new ArrayList<>();
        // add CMAC + HMAC
        rules.addAll(List.of(CMAC, CMAC_MSG, HMAC, HMAC_MSG));

        // add "simple" MACs
        for (final String mac : PythonCryptoMac.simpleMACs) {
            rules.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("Crypto.Hash." + mac, "Cryptodome.Hash." + mac)
                            .forMethods("new")
                            .shouldBeDetectedAs(new ValueActionFactory<>(mac))
                            .withAnyParameters()
                            .buildForContext(new MacContext())
                            .inBundle(() -> "PyCrypto")
                            .withoutDependingDetectionRules());
        }
        return rules;
    }
}
