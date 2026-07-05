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
package com.ibm.plugin.rules.detection.fernet;

import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.CipherActionFactory;
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class PycaFernet {

    private PycaFernet() {
        // private
    }

    private static @Nonnull List<IDetectionRule<Tree>> encryptDecryptFernet() {
        List<String> methodNames =
                List.of("encrypt", "encrypt_at_time", "decrypt", "decrypt_at_time");
        List<String> objectNames = List.of("Fernet", "MultiFernet");
        List<IDetectionRule<Tree>> rules = new LinkedList<>();

        for (String method : methodNames) {
            for (String object : objectNames) {
                rules.add(
                        new DetectionRuleBuilder<Tree>()
                                .createDetectionRule()
                                .forObjectTypes("cryptography.fernet." + object)
                                .forMethods(method)
                                .shouldBeDetectedAs(
                                        new CipherActionFactory<>(
                                                method.startsWith("encrypt")
                                                        ? CipherAction.Action.ENCRYPT
                                                        : CipherAction.Action.DECRYPT))
                                .withAnyParameters()
                                .buildForContext(new CipherContext(Map.of("algorithm", "Fernet")))
                                .inBundle(() -> "Pyca")
                                .withoutDependingDetectionRules());
            }
        }
        return rules;
    }

    private static final IDetectionRule<Tree> GENERATION_FERNET =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("cryptography.fernet.Fernet")
                    .forMethods("generate_key")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.GENERATION))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("algorithm", "Fernet")))
                    .inBundle(() -> "Pyca")
                    .withDependingDetectionRules(encryptDecryptFernet());

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(PycaFernet::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(GENERATION_FERNET);
    }
}
