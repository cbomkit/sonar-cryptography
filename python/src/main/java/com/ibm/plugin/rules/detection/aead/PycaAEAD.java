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
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.engine.model.factory.CipherActionFactory;
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class PycaAEAD {

    private PycaAEAD() {
        // private
    }

    private static final String TYPE =
            "cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305";

    private static final IDetectionRule<Tree> ENCRYPT_CHACHA20POLY1305 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(TYPE)
                    .forMethods("encrypt")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withAnyParameters()
                    .buildForContext(new CipherContext(Map.of("algorithm", "ChaCha20Poly1305")))
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> DECRYPT_CHACHA20POLY1305 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(TYPE)
                    .forMethods("decrypt")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withAnyParameters()
                    .buildForContext(new CipherContext(Map.of("algorithm", "ChaCha20Poly1305")))
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> GENERATION_CHACHA20POLY1305 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(TYPE)
                    .forMethods("generate_key")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.GENERATION))
                    .withAnyParameters()
                    .buildForContext(
                            new SecretKeyContext(
                                    Map.of("algorithm", "ChaCha20Poly1305", "kind", "AEAD")))
                    .inBundle(() -> "Pyca")
                    .withDependingDetectionRules(
                            List.of(ENCRYPT_CHACHA20POLY1305, DECRYPT_CHACHA20POLY1305));

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(PycaAEAD::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(GENERATION_CHACHA20POLY1305);
    }
}
