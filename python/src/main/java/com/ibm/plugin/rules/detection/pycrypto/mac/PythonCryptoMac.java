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

import com.ibm.engine.model.Size.UnitType;
import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.DigestSizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class PythonCryptoMac extends DetectionRuleSet<Tree> {

    private PythonCryptoMac() {
        // private
    }

    private static final IDetectionRule<Tree> CMAC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Hash.CMAC", "Cryptodome.Hash.CMAC")
                    .forMethods("new")
                    .withNamedMethodParameter("key", ANY)
                    .withOptionalNamedMethodParameter("msg", ANY)
                    .withOptionalNamedMethodParameter(
                            "ciphermod", ANY) // Crypto.Hash.* or Cryptodome.Hash.*
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withOptionalNamedMethodParameter("cipher_params", ANY)
                    .withOptionalNamedMethodParameter("mac_len", "int")
                    .shouldBeDetectedAs(new DigestSizeFactory<>(UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("update_after_digest", ANY)
                    .buildForContext(new MacContext(Map.of("kind", "cmac")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> HMAC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Hash.HMAC", "Cryptodome.Hash.HMAC")
                    .forMethods("new")
                    .withNamedMethodParameter("key", ANY)
                    .withOptionalNamedMethodParameter("msg", ANY)
                    .withOptionalNamedMethodParameter(
                            "digestmod", ANY) // Crypto.Hash.* or Cryptodome.Hash.*
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new MacContext(Map.of("kind", "hmac")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules() {
        List<IDetectionRule<Tree>> rules = new ArrayList<>();
        // add CMAC + HMAC
        rules.addAll(List.of(CMAC, HMAC));

        // add "simple" MACs
        for (final String mac : List.of("KMAC128", "KMAC256", "Poly1305")) {
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
