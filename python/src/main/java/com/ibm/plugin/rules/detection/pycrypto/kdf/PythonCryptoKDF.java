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
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class PythonCryptoKDF extends DetectionRuleSet<Tree> {

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
                    .withNamedMethodParameter("password", ANY)
                    .withNamedMethodParameter("salt", ANY)
                    .withNamedMethodParameter("dkLen", "int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("count", "int")
                    .shouldBeDetectedAs(new IterationCountFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("hashAlgo", ANY)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
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
                    .withNamedMethodParameter("password", ANY)
                    .withNamedMethodParameter("salt", ANY)
                    .withOptionalNamedMethodParameter("dkLen", "int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("count", "int")
                    .shouldBeDetectedAs(new IterationCountFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("hmac_hash_module", ANY)
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
                    .withNamedMethodParameter("password", ANY)
                    .withNamedMethodParameter("salt", ANY)
                    .withNamedMethodParameter("key_len", "int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withNamedMethodParameter("N", "int")
                    .withNamedMethodParameter("r", "int")
                    .withNamedMethodParameter("p", "int")
                    .withOptionalNamedMethodParameter("num_keys", "int")
                    .buildForContext(new KeyDerivationFunctionContext(Map.of("kind", "scrypt")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> HKDF =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Protocol.KDF", "Cryptodome.Protocol.KDF")
                    .forMethods("HKDF")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HKDF"))
                    .withNamedMethodParameter("master", ANY)
                    .withNamedMethodParameter("key_len", "int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withNamedMethodParameter("salt", ANY)
                    .withNamedMethodParameter(
                            "hashmod", ANY) // Crypto.Hash.* or Cryptodome.Hash.* (hash_mod)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("num_keys", "int")
                    .withOptionalNamedMethodParameter("context", ANY)
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
                    .withNamedMethodParameter("master", ANY) // master
                    .withNamedMethodParameter("key_len", "int") // key_len
                    .shouldBeDetectedAs(new KeySizeFactory<>(UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withNamedMethodParameter("prf", ANY)
                    .withOptionalNamedMethodParameter("num_keys", "int")
                    .withOptionalNamedMethodParameter("label", ANY)
                    .withOptionalNamedMethodParameter("context", ANY)
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules() {
        return List.of(PBKDF1, PBKDF2, SCRYPT, HKDF, SP800_108_COUNTER);
    }
}
