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
package com.ibm.plugin.rules.detection.pycrypto.kdf;

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.model.Size;
import com.ibm.engine.model.Size.UnitType;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.IterationCountFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
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
public final class PythonCryptoKDF {

    private PythonCryptoKDF() {
        // private
    }

    // PBKDF1 - module function call
    private static final IDetectionRule<Tree> PBKDF1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Protocol.KDF", "Cryptodome.Protocol.KDF")
                    .forMethods("PBKDF1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF1"))
                    .withMethodParameter(ANY) // password
                    .withMethodParameter(ANY) // salt
                    .withMethodParameter("int") // dkLen
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(
                            new KeyDerivationFunctionContext(Map.of("kind", "pycrypto-pbkdf1")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PBKDF1_WITH_COUNT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Protocol.KDF", "Cryptodome.Protocol.KDF")
                    .forMethods("PBKDF1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF1"))
                    .withMethodParameter(ANY) // password
                    .withMethodParameter(ANY) // salt
                    .withMethodParameter("int") // dkLen
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("int") // count
                    .shouldBeDetectedAs(new IterationCountFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(
                            new KeyDerivationFunctionContext(Map.of("kind", "pycrypto-pbkdf1")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PBKDF1_WITH_HASH =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Protocol.KDF", "Cryptodome.Protocol.KDF")
                    .forMethods("PBKDF1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF1"))
                    .withMethodParameter(ANY) // password
                    .withMethodParameter(ANY) // salt
                    .withMethodParameter("int") // dkLen
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(ANY) // Crypto.Hash.* or Cryptodome.Hash.* (hashAlgo)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(
                            new KeyDerivationFunctionContext(Map.of("kind", "pycrypto-pbkdf1")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PBKDF1_WITH_COUNT_AND_HASH =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Protocol.KDF", "Cryptodome.Protocol.KDF")
                    .forMethods("PBKDF1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF1"))
                    .withMethodParameter(ANY) // password
                    .withMethodParameter(ANY) // salt
                    .withMethodParameter("int") // dkLen
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("int") // count
                    .shouldBeDetectedAs(new IterationCountFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(ANY) // Crypto.Hash.* or Cryptodome.Hash.* (hashAlgo)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(
                            new KeyDerivationFunctionContext(Map.of("kind", "pycrypto-pbkdf1")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PBKDF1_WITH_HASH_AND_COUNT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Protocol.KDF", "Cryptodome.Protocol.KDF")
                    .forMethods("PBKDF1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF1"))
                    .withMethodParameter(ANY) // password
                    .withMethodParameter(ANY) // salt
                    .withMethodParameter("int") // dkLen
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(ANY) // Crypto.Hash.* or Cryptodome.Hash.* (hashAlgo)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("int") // count
                    .shouldBeDetectedAs(new IterationCountFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(
                            new KeyDerivationFunctionContext(Map.of("kind", "pycrypto-pbkdf1")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    // PBKDF2 - module function call
    private static final IDetectionRule<Tree> PBKDF2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Protocol.KDF", "Cryptodome.Protocol.KDF")
                    .forMethods("PBKDF2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2"))
                    .withMethodParameter(ANY) // password
                    .withMethodParameter(ANY) // salt
                    .withMethodParameter("int") // dkLen
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(
                            new KeyDerivationFunctionContext(Map.of("kind", "pycrypto-pbkdf2")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PBKDF2_WITH_COUNT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Protocol.KDF", "Cryptodome.Protocol.KDF")
                    .forMethods("PBKDF2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2"))
                    .withMethodParameter(ANY) // password
                    .withMethodParameter(ANY) // salt
                    .withMethodParameter("int") // dkLen
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("int") // count
                    .shouldBeDetectedAs(new IterationCountFactory<>())
                    .buildForContext(
                            new KeyDerivationFunctionContext(Map.of("kind", "pycrypto-pbkdf2")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PBKDF2_WITH_HASH =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Protocol.KDF", "Cryptodome.Protocol.KDF")
                    .forMethods("PBKDF2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2"))
                    .withMethodParameter(ANY) // password
                    .withMethodParameter(ANY) // salt
                    .withMethodParameter("int") // dkLen
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(ANY) // Crypto.Hash.* or Cryptodome.Hash.* (hashAlgo)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(
                            new KeyDerivationFunctionContext(Map.of("kind", "pycrypto-pbkdf2")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PBKDF2_WITH_HASH_AND_COUNT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Protocol.KDF", "Cryptodome.Protocol.KDF")
                    .forMethods("PBKDF2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2"))
                    .withMethodParameter(ANY) // password
                    .withMethodParameter(ANY) // salt
                    .withMethodParameter("int") // dkLen
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(ANY) // Crypto.Hash.* or Cryptodome.Hash.* (hashAlgo)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("int") // count
                    .shouldBeDetectedAs(new IterationCountFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(
                            new KeyDerivationFunctionContext(Map.of("kind", "pycrypto-pbkdf2")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PBKDF2_WITH_COUNT_AND_HASH =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Protocol.KDF", "Cryptodome.Protocol.KDF")
                    .forMethods("PBKDF2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2"))
                    .withMethodParameter(ANY) // password
                    .withMethodParameter(ANY) // salt
                    .withMethodParameter("int") // dkLen
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("int") // count
                    .shouldBeDetectedAs(new IterationCountFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(ANY) // Crypto.Hash.* or Cryptodome.Hash.* (hashAlgo)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(
                            new KeyDerivationFunctionContext(Map.of("kind", "pycrypto-pbkdf2")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    // scrypt - module function call
    private static final IDetectionRule<Tree> SCRYPT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Protocol.KDF", "Cryptodome.Protocol.KDF")
                    .forMethods("scrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("scrypt"))
                    .withMethodParameter(ANY) // password
                    .withMethodParameter(ANY) // salt
                    .withMethodParameter("int") // key_len
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("int") // N
                    .withMethodParameter("int") // r
                    .withMethodParameter("int") // p
                    .withOtherParameters() // num_keys
                    .buildForContext(new KeyDerivationFunctionContext(Map.of("kind", "scrypt")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> HKDF =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Protocol.KDF", "Cryptodome.Protocol.KDF")
                    .forMethods("HKDF")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HKDF"))
                    .withMethodParameter(ANY) // master
                    .withMethodParameter("int") // keylen
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(ANY) // salt
                    .withMethodParameter(ANY) // Crypto.Hash.* or Cryptodome.Hash.* (hash_mod)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(
                            new KeyDerivationFunctionContext(Map.of("kind", "pycrypto-hkdf")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    // scrypt - module function call
    private static final IDetectionRule<Tree> SP800_108_COUNTER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Protocol.KDF", "Cryptodome.Protocol.KDF")
                    .forMethods("SP800_108_Counter")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SP800_108_Counter"))
                    .withMethodParameter(ANY) // master
                    .withMethodParameter("int") // key_len
                    .shouldBeDetectedAs(new KeySizeFactory<>(UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(ANY) // prf
                    .withOtherParameters() // num_keys, label
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(PythonCryptoKDF::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(
                PBKDF1,
                PBKDF1_WITH_HASH,
                PBKDF1_WITH_COUNT,
                PBKDF1_WITH_HASH_AND_COUNT,
                PBKDF1_WITH_COUNT_AND_HASH,
                PBKDF2,
                PBKDF2_WITH_HASH,
                PBKDF2_WITH_COUNT,
                PBKDF2_WITH_HASH_AND_COUNT,
                PBKDF2_WITH_COUNT_AND_HASH,
                SCRYPT,
                HKDF,
                SP800_108_COUNTER);
    }
}
