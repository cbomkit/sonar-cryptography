/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
package com.ibm.plugin.rules.detection.pycrypto.keyagreement;

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.pycrypto.publickey.PythonCryptoPublicKey;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class PythonCryptoKeyAgreement {

    private PythonCryptoKeyAgreement() {
        // private
    }

    private static final IDetectionRule<Tree> IMPORT_X25519_PUBLIC_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Protocol.DH", "Cryptodome.Protocol.DH")
                    .forMethods("import_x25519_public_key")
                    .shouldBeDetectedAs(
                            new KeyActionFactory<>(KeyAction.Action.PUBLIC_KEY_GENERATION))
                    .withAnyParameters()
                    .buildForContext(new PublicKeyContext(Map.of("algorithm", "Curve25519")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> IMPORT_X25519_PRIVATE_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Protocol.DH", "Cryptodome.Protocol.DH")
                    .forMethods("import_x25519_private_key")
                    .shouldBeDetectedAs(
                            new KeyActionFactory<>(KeyAction.Action.PRIVATE_KEY_GENERATION))
                    .withAnyParameters()
                    .buildForContext(new PrivateKeyContext(Map.of("algorithm", "Curve25519")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> IMPORT_X448_PUBLIC_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Protocol.DH", "Cryptodome.Protocol.DH")
                    .forMethods("import_x448_public_key")
                    .shouldBeDetectedAs(
                            new KeyActionFactory<>(KeyAction.Action.PUBLIC_KEY_GENERATION))
                    .withAnyParameters()
                    .buildForContext(new PublicKeyContext(Map.of("algorithm", "Curve448")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> IMPORT_X448_PRIVATE_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Protocol.DH", "Cryptodome.Protocol.DH")
                    .forMethods("import_x448_private_key")
                    .shouldBeDetectedAs(
                            new KeyActionFactory<>(KeyAction.Action.PRIVATE_KEY_GENERATION))
                    .withAnyParameters()
                    .buildForContext(new PrivateKeyContext(Map.of("algorithm", "Curve448")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    // DH.key_agreement - module function call
    private static final IDetectionRule<Tree> DH_KEY_AGREEMENT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Protocol.DH", "Cryptodome.Protocol.DH")
                    .forMethods("key_agreement")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDH"))
                    .withMethodParameter(ANY) // kdf
                    .withMethodParameter(
                            ANY) // Crypto.PublicKey.ECC.ECCKey or Cryptodome.PublicKey.ECC.ECCKey
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(
                            Stream.concat(
                                            PythonCryptoPublicKey.ECCRules().stream(),
                                            Stream.of(
                                                    IMPORT_X25519_PRIVATE_KEY,
                                                    IMPORT_X448_PRIVATE_KEY))
                                    .toList())
                    .withMethodParameter(
                            ANY) // Crypto.PublicKey.ECC.ECCKey or Cryptodome.PublicKey.ECC.ECCKey
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(
                            Stream.concat(
                                            PythonCryptoPublicKey.ECCRules().stream(),
                                            Stream.of(
                                                    IMPORT_X25519_PUBLIC_KEY,
                                                    IMPORT_X448_PUBLIC_KEY))
                                    .toList())
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(PythonCryptoKeyAgreement::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(DH_KEY_AGREEMENT);
    }
}
