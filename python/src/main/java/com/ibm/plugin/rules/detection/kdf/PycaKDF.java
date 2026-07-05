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
package com.ibm.plugin.rules.detection.kdf;

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.model.AlgorithmParameter;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.AlgorithmParameterFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.ModeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class PycaKDF {

    private PycaKDF() {
        // private
    }

    private static final String HASH_TYPE = "cryptography.hazmat.primitives.hashes.*";
    private static final String KDF_TYPE_PREFIX = "cryptography.hazmat.primitives.kdf.";

    private static final IDetectionRule<Tree> X963KDF =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(KDF_TYPE_PREFIX + "x963kdf")
                    .forMethods("X963KDF")
                    .withMethodParameter(HASH_TYPE) // Accepts only hashes (not pre-hashes)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(0)
                    .withMethodParameter(ANY)
                    .buildForContext(new KeyDerivationFunctionContext(Map.of("kind", "x963")))
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> KBKDFCMAC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(KDF_TYPE_PREFIX + "kbkdf")
                    .forMethods("KBKDFCMAC")
                    .withMethodParameter("cryptography.hazmat.primitives.ciphers.algorithms.*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter(ANY)
                    .shouldBeDetectedAs(new ModeFactory<>())
                    .asChildOfParameterWithId(0)
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(0)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .buildForContext(new KeyDerivationFunctionContext(Map.of("kind", "cmac")))
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> KBKDFHMAC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(KDF_TYPE_PREFIX + "kbkdf")
                    .forMethods("KBKDFHMAC")
                    .withMethodParameter(HASH_TYPE) // Accepts only hashes (not pre-hashes)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter(ANY)
                    .shouldBeDetectedAs(new ModeFactory<>())
                    .asChildOfParameterWithId(0)
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(0)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .buildForContext(new KeyDerivationFunctionContext(Map.of("kind", "hmac")))
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> HKDF_EXPAND =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(KDF_TYPE_PREFIX + "hkdf")
                    .forMethods("HKDFExpand")
                    .withMethodParameter(HASH_TYPE) // Accepts only hashes (not pre-hashes)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(0)
                    .withMethodParameter(ANY)
                    .buildForContext(new KeyDerivationFunctionContext(Map.of("kind", "hkdf")))
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> HKDF =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(KDF_TYPE_PREFIX + "hkdf")
                    .forMethods("HKDF")
                    .withMethodParameter(HASH_TYPE) // Accepts only hashes (not pre-hashes)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(0)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .buildForContext(new KeyDerivationFunctionContext(Map.of("kind", "hkdf")))
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CONCAT_KDF_HMAC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(KDF_TYPE_PREFIX + "concatkdf")
                    .forMethods("ConcatKDFHMAC")
                    .withMethodParameter(HASH_TYPE) // Accepts only hashes (not pre-hashes)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(0)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .buildForContext(new KeyDerivationFunctionContext(Map.of("kind", "concatkdf")))
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CONCAT_KDF =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(KDF_TYPE_PREFIX + "concatkdf")
                    .forMethods("ConcatKDFHash")
                    .withMethodParameter(HASH_TYPE) // Accepts only hashes (not pre-hashes)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(0)
                    .withMethodParameter(ANY)
                    .buildForContext(new KeyDerivationFunctionContext(Map.of("kind", "concatkdf")))
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SCRYPT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(KDF_TYPE_PREFIX + "scrypt")
                    .forMethods("Scrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("Scrypt"))
                    .withMethodParameter(ANY)
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(0)
                    .withMethodParameter("int")
                    .withMethodParameter("int")
                    .withMethodParameter("int")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PBKDF2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(KDF_TYPE_PREFIX + "pbkdf2")
                    .forMethods("PBKDF2HMAC")
                    .withMethodParameter(HASH_TYPE) // Accepts only hashes (not pre-hashes)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(0)
                    .withMethodParameter(ANY)
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(
                            new AlgorithmParameterFactory<>(AlgorithmParameter.Kind.ITERATIONS))
                    .asChildOfParameterWithId(0)
                    .buildForContext(new KeyDerivationFunctionContext(Map.of("kind", "pbkdf2")))
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(PycaKDF::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(
                PBKDF2,
                SCRYPT,
                CONCAT_KDF,
                CONCAT_KDF_HMAC,
                HKDF,
                HKDF_EXPAND,
                KBKDFHMAC,
                KBKDFCMAC,
                X963KDF);
    }
}
