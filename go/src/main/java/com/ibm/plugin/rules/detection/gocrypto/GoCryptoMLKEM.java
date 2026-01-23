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
package com.ibm.plugin.rules.detection.gocrypto;

import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

/**
 * Detection rules for Go's crypto/mlkem package (NIST FIPS 203).
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>mlkem.GenerateKey768() - generates an ML-KEM-768 decapsulation key
 *   <li>mlkem.GenerateKey1024() - generates an ML-KEM-1024 decapsulation key
 *   <li>mlkem.NewDecapsulationKey768(seed) - creates ML-KEM-768 decapsulation key from seed
 *   <li>mlkem.NewDecapsulationKey1024(seed) - creates ML-KEM-1024 decapsulation key from seed
 *   <li>mlkem.NewEncapsulationKey768(key) - parses an ML-KEM-768 encapsulation key
 *   <li>mlkem.NewEncapsulationKey1024(key) - parses an ML-KEM-1024 encapsulation key
 *   <li>DecapsulationKey768.Decapsulate(ciphertext) - decapsulates a shared key
 *   <li>DecapsulationKey1024.Decapsulate(ciphertext) - decapsulates a shared key
 *   <li>DecapsulationKey768.EncapsulationKey() - derives encapsulation key
 *   <li>DecapsulationKey1024.EncapsulationKey() - derives encapsulation key
 *   <li>EncapsulationKey768.Encapsulate() - encapsulates a shared key
 *   <li>EncapsulationKey1024.Encapsulate() - encapsulates a shared key
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class GoCryptoMLKEM {

    private GoCryptoMLKEM() {
        // private
    }

    // EncapsulationKey768.Encapsulate() (sharedKey, ciphertext []byte)
    // Encapsulates a shared key using the ML-KEM-768 encapsulation key
    private static final IDetectionRule<Tree> ENCAPSULATE_768 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("*mlkem.EncapsulationKey768", "mlkem.EncapsulationKey768")
                    .forMethods("Encapsulate")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.ENCAPSULATION))
                    .withoutParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // EncapsulationKey1024.Encapsulate() (sharedKey, ciphertext []byte)
    // Encapsulates a shared key using the ML-KEM-1024 encapsulation key
    private static final IDetectionRule<Tree> ENCAPSULATE_1024 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("*mlkem.EncapsulationKey1024", "mlkem.EncapsulationKey1024")
                    .forMethods("Encapsulate")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.ENCAPSULATION))
                    .withoutParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // DecapsulationKey768.Decapsulate(ciphertext []byte) (sharedKey []byte, err error)
    // Decapsulates a shared key from a ciphertext
    private static final IDetectionRule<Tree> DECAPSULATE_768 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("*mlkem.DecapsulationKey768", "mlkem.DecapsulationKey768")
                    .forMethods("Decapsulate")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.DECAPSULATION))
                    .withMethodParameter("[]byte")
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // DecapsulationKey1024.Decapsulate(ciphertext []byte) (sharedKey []byte, err error)
    // Decapsulates a shared key from a ciphertext
    private static final IDetectionRule<Tree> DECAPSULATE_1024 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("*mlkem.DecapsulationKey1024", "mlkem.DecapsulationKey1024")
                    .forMethods("Decapsulate")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.DECAPSULATION))
                    .withMethodParameter("[]byte")
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // DecapsulationKey768.EncapsulationKey() *EncapsulationKey768
    // Derives the public encapsulation key from the decapsulation key
    private static final IDetectionRule<Tree> ENCAPSULATION_KEY_768 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("*mlkem.DecapsulationKey768", "mlkem.DecapsulationKey768")
                    .forMethods("EncapsulationKey")
                    .shouldBeDetectedAs(
                            new KeyActionFactory<>(KeyAction.Action.PUBLIC_KEY_GENERATION))
                    .withoutParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "GoCrypto")
                    .withDependingDetectionRules(List.of(ENCAPSULATE_768));

    // DecapsulationKey1024.EncapsulationKey() *EncapsulationKey1024
    // Derives the public encapsulation key from the decapsulation key
    private static final IDetectionRule<Tree> ENCAPSULATION_KEY_1024 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("*mlkem.DecapsulationKey1024", "mlkem.DecapsulationKey1024")
                    .forMethods("EncapsulationKey")
                    .shouldBeDetectedAs(
                            new KeyActionFactory<>(KeyAction.Action.PUBLIC_KEY_GENERATION))
                    .withoutParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "GoCrypto")
                    .withDependingDetectionRules(List.of(ENCAPSULATE_1024));

    // mlkem.GenerateKey768() (*DecapsulationKey768, error)
    // Generates a new ML-KEM-768 decapsulation key
    private static final IDetectionRule<Tree> GENERATE_KEY_768 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/mlkem")
                    .forMethods("GenerateKey768")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM-768"))
                    .withoutParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "GoCrypto")
                    .withDependingDetectionRules(List.of(DECAPSULATE_768, ENCAPSULATION_KEY_768));

    // mlkem.GenerateKey1024() (*DecapsulationKey1024, error)
    // Generates a new ML-KEM-1024 decapsulation key
    private static final IDetectionRule<Tree> GENERATE_KEY_1024 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/mlkem")
                    .forMethods("GenerateKey1024")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM-1024"))
                    .withoutParameters()
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "GoCrypto")
                    .withDependingDetectionRules(List.of(DECAPSULATE_1024, ENCAPSULATION_KEY_1024));

    // mlkem.NewDecapsulationKey768(seed []byte) (*DecapsulationKey768, error)
    // Creates a decapsulation key from a 64-byte seed
    private static final IDetectionRule<Tree> NEW_DECAPSULATION_KEY_768 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/mlkem")
                    .forMethods("NewDecapsulationKey768")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM-768"))
                    .withMethodParameter("[]byte")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "GoCrypto")
                    .withDependingDetectionRules(List.of(DECAPSULATE_768, ENCAPSULATION_KEY_768));

    // mlkem.NewDecapsulationKey1024(seed []byte) (*DecapsulationKey1024, error)
    // Creates a decapsulation key from a 64-byte seed
    private static final IDetectionRule<Tree> NEW_DECAPSULATION_KEY_1024 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/mlkem")
                    .forMethods("NewDecapsulationKey1024")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM-1024"))
                    .withMethodParameter("[]byte")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "GoCrypto")
                    .withDependingDetectionRules(List.of(DECAPSULATE_1024, ENCAPSULATION_KEY_1024));

    // mlkem.NewEncapsulationKey768(encapsulationKey []byte) (*EncapsulationKey768, error)
    // Parses an encapsulation key from its encoded form
    private static final IDetectionRule<Tree> NEW_ENCAPSULATION_KEY_768 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/mlkem")
                    .forMethods("NewEncapsulationKey768")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM-768"))
                    .withMethodParameter("[]byte")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "GoCrypto")
                    .withDependingDetectionRules(List.of(ENCAPSULATE_768));

    // mlkem.NewEncapsulationKey1024(encapsulationKey []byte) (*EncapsulationKey1024, error)
    // Parses an encapsulation key from its encoded form
    private static final IDetectionRule<Tree> NEW_ENCAPSULATION_KEY_1024 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/mlkem")
                    .forMethods("NewEncapsulationKey1024")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM-1024"))
                    .withMethodParameter("[]byte")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                    .inBundle(() -> "GoCrypto")
                    .withDependingDetectionRules(List.of(ENCAPSULATE_1024));

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(
                GENERATE_KEY_768,
                GENERATE_KEY_1024,
                NEW_DECAPSULATION_KEY_768,
                NEW_DECAPSULATION_KEY_1024,
                NEW_ENCAPSULATION_KEY_768,
                NEW_ENCAPSULATION_KEY_1024);
    }
}
