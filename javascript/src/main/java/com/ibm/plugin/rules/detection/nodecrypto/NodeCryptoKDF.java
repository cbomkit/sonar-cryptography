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
package com.ibm.plugin.rules.detection.nodecrypto;

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.model.AlgorithmParameter;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.AlgorithmParameterFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.SaltSizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.javascript.api.Tree;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/**
 * Detection rules for Node.js key derivation function APIs.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>crypto.pbkdf2(password, salt, iterations, keylen, digest, callback)
 *   <li>crypto.pbkdf2Sync(password, salt, iterations, keylen, digest)
 *   <li>crypto.scrypt(password, salt, keylen, callback)
 *   <li>crypto.scryptSync(password, salt, keylen)
 *   <li>crypto.hkdfSync(digest, ikm, salt, info, keylen)
 *   <li>crypto.hkdf(digest, ikm, salt, info, keylen, callback)
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class NodeCryptoKDF {

    private NodeCryptoKDF() {
        // private
    }

    private static final IDetectionRule<Tree> PBKDF2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("pbkdf2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2"))
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .shouldBeDetectedAs(new SaltSizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("number")
                    .shouldBeDetectedAs(
                            new AlgorithmParameterFactory<>(AlgorithmParameter.Kind.ITERATIONS))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("number")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("string")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(ANY)
                    .buildForContext(new KeyDerivationFunctionContext(Map.of("kind", "pbkdf2")))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PBKDF2_SYNC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("pbkdf2Sync")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2"))
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .shouldBeDetectedAs(new SaltSizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("number")
                    .shouldBeDetectedAs(
                            new AlgorithmParameterFactory<>(AlgorithmParameter.Kind.ITERATIONS))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("number")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("string")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new KeyDerivationFunctionContext(Map.of("kind", "pbkdf2")))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SCRYPT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("scrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("Scrypt"))
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .shouldBeDetectedAs(new SaltSizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("number")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(ANY)
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SCRYPT_SYNC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("scryptSync")
                    .shouldBeDetectedAs(new ValueActionFactory<>("Scrypt"))
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .shouldBeDetectedAs(new SaltSizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("number")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> HKDF =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("hkdf")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HKDF"))
                    .withMethodParameter("string")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .withMethodParameter("number")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(ANY)
                    .buildForContext(new KeyDerivationFunctionContext(Map.of("kind", "hkdf")))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> HKDF_SYNC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(NodeCryptoTypes.CRYPTO, NodeCryptoTypes.NODE_CRYPTO)
                    .forMethods("hkdfSync")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HKDF"))
                    .withMethodParameter("string")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .withMethodParameter("number")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new KeyDerivationFunctionContext(Map.of("kind", "hkdf")))
                    .inBundle(() -> NodeCryptoTypes.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(NodeCryptoKDF::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(PBKDF2, PBKDF2_SYNC, SCRYPT, SCRYPT_SYNC, HKDF, HKDF_SYNC);
    }
}
