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
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
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
                            "ciphermod", ANY) // Crypto.Cipher.* or Cryptodome.Cipher.*
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("cipher_params", ANY)
                    .withOptionalNamedMethodParameter("mac_len", "int")
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

    // The output length (mac_len) is not captured, as it cannot be exported to the CBOM.
    private static final IDetectionRule<Tree> KMAC128 = kmac("KMAC128");

    private static final IDetectionRule<Tree> KMAC256 = kmac("KMAC256");

    private static final IDetectionRule<Tree> POLY1305 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Hash.Poly1305", "Cryptodome.Hash.Poly1305")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("Poly1305"))
                    .withNamedMethodParameter("key", ANY)
                    .withOptionalNamedMethodParameter(
                            "cipher", ANY) // Crypto.Cipher.AES or Crypto.Cipher.ChaCha20
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("nonce", ANY)
                    .withOptionalNamedMethodParameter("data", ANY)
                    .buildForContext(new MacContext(Map.of("kind", "poly1305")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    private static IDetectionRule<Tree> kmac(@Nonnull String name) {
        return new DetectionRuleBuilder<Tree>()
                .createDetectionRule()
                .forObjectTypes("Crypto.Hash." + name, "Cryptodome.Hash." + name)
                .forMethods("new")
                .shouldBeDetectedAs(new ValueActionFactory<>(name))
                .withNamedMethodParameter("key", ANY)
                .withOptionalNamedMethodParameter("data", ANY)
                .withOptionalNamedMethodParameter("mac_len", "int")
                .withOptionalNamedMethodParameter("custom", ANY)
                .buildForContext(new MacContext())
                .inBundle(() -> "PyCrypto")
                .withoutDependingDetectionRules();
    }

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules() {
        return List.of(CMAC, HMAC, KMAC128, KMAC256, POLY1305);
    }
}
