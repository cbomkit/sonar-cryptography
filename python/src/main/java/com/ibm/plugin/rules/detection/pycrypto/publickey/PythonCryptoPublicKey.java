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
package com.ibm.plugin.rules.detection.pycrypto.publickey;

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.engine.model.factory.CurveFactory;
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

// Only the ElGamal rules are registered as top-level detection rules. The documentation
// describes them as obsolete keys. Pycryptodome does not provide a higher-level method
// (encryption, signature) based on ElGamal keys.
//
// For RSA, DSA, and ECC keys there are corresponding signature or encryption schemes
// that use them as a parameter. In order the detect the key object in the context of
// these higher-level methods the corresponding rules are used as dependent rules.
@SuppressWarnings("java:S1192")
public final class PythonCryptoPublicKey {

    private PythonCryptoPublicKey() {
        // private
    }

    // RSA generate -> private key
    private static final IDetectionRule<Tree> RSA_GENERATE =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.PublicKey.RSA", "Cryptodome.PublicKey.RSA")
                    .forMethods("generate")
                    //     .shouldBeDetectedAs(
                    //             new KeyActionFactory<>(KeyAction.Action.PRIVATE_KEY_GENERATION))
                    .withMethodParameter("int") // keylen
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .asChildOfParameterWithId(-1)
                    .withOtherParameters() // randfunc, e
                    .buildForContext(new PrivateKeyContext(Map.of("algorithm", "RSA")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    // RSA construct and import_key -> public or private key
    private static final IDetectionRule<Tree> RSA_CONSTRUCT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.PublicKey.RSA", "Cryptodome.PublicKey.RSA")
                    .forMethods("construct", "import_key")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.GENERATION))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("algorithm", "RSA")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    // RsaKey public_key -> public key
    private static final IDetectionRule<Tree> RSA_PUBLIC_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "Crypto.PublicKey.RSA.RsaKey", "Cryptodome.PublicKey.RSA.RsaKey")
                    .forMethods("public_key")
                    .shouldBeDetectedAs(
                            new KeyActionFactory<>(KeyAction.Action.PUBLIC_KEY_GENERATION))
                    .withoutParameters()
                    .buildForContext(new PublicKeyContext(Map.of("algorithm", "RSA")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    // DSA generate -> private key
    private static final IDetectionRule<Tree> DSA_GENERATE =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.PublicKey.DSA", "Cryptodome.PublicKey.DSA")
                    .forMethods("generate")
                    //     .shouldBeDetectedAs(
                    //             new KeyActionFactory<>(KeyAction.Action.PRIVATE_KEY_GENERATION))
                    .withMethodParameter("int") // keylen
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .asChildOfParameterWithId(-1)
                    .withOtherParameters() // randfunc, domain
                    .buildForContext(new PrivateKeyContext(Map.of("algorithm", "DSA")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    // DSA construct and import_key -> public or private key
    private static final IDetectionRule<Tree> DSA_CONSTRUCT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.PublicKey.DSA", "Cryptodome.PublicKey.DSA")
                    .forMethods("construct", "import_key")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.GENERATION))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("algorithm", "DSA")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    // DsaKey public_key -> public key
    private static final IDetectionRule<Tree> DSA_PUBLIC_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "Crypto.PublicKey.DSA.DsaKey", "Cryptodome.PublicKey.DSA.DsaKey")
                    .forMethods("public_key")
                    .shouldBeDetectedAs(
                            new KeyActionFactory<>(KeyAction.Action.PUBLIC_KEY_GENERATION))
                    .withoutParameters()
                    .buildForContext(new PublicKeyContext(Map.of("algorithm", "DSA")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    // ECC key generation
    private static final IDetectionRule<Tree> ECC_GENERATE =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.PublicKey.ECC", "Cryptodome.PublicKey.ECC")
                    .forMethods("generate")
                    // .shouldBeDetectedAs(new
                    // KeyActionFactory<>(KeyAction.Action.PRIVATE_KEY_GENERATION))
                    // signature is **kwargs!
                    .withMethodParameter("str") // assuming curve as 1st parameter
                    .shouldBeDetectedAs(new CurveFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOtherParameters() // randfunc
                    .buildForContext(new PrivateKeyContext(Map.of("algorithm", "EC")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    // ECC key construction
    private static final IDetectionRule<Tree> ECC_CONSTRUCT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.PublicKey.ECC", "Cryptodome.PublicKey.ECC")
                    .forMethods("construct")
                    //     .shouldBeDetectedAs(
                    //             new KeyActionFactory<>(KeyAction.Action.PRIVATE_KEY_GENERATION))
                    .withMethodParameter("str") // curve
                    .shouldBeDetectedAs(new CurveFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOtherParameters() // d, seed, point_x, point_y
                    .buildForContext(new KeyContext(Map.of("algorithm", "EC")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    // ECC import
    private static final IDetectionRule<Tree> ECC_IMPORT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.PublicKey.ECC", "Cryptodome.PublicKey.ECC")
                    .forMethods("import_key")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.GENERATION))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("algorithm", "EC")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    // EccKey public_key -> public key
    private static final IDetectionRule<Tree> ECC_PUBLIC_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "Crypto.PublicKey.ECC.EccKey", "Cryptodome.PublicKey.ECC.EccKey")
                    .forMethods("public_key")
                    .shouldBeDetectedAs(
                            new KeyActionFactory<>(KeyAction.Action.PUBLIC_KEY_GENERATION))
                    .withoutParameters()
                    .buildForContext(new PublicKeyContext(Map.of("algorithm", "EC")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    // ElGamal
    private static final IDetectionRule<Tree> ELGAMAL_GENERATE =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.PublicKey.ElGamal", "Cryptodome.PublicKey.ElGamal")
                    .forMethods("generate")
                    //     .shouldBeDetectedAs(
                    //             new KeyActionFactory<>(KeyAction.Action.PRIVATE_KEY_GENERATION))
                    .withMethodParameter("int") // bits
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(ANY) // randfunc
                    .buildForContext(new PrivateKeyContext(Map.of("algorithm", "ElGamal")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    // ElGamal
    private static final IDetectionRule<Tree> ELGAMAL_CONSTRUCT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.PublicKey.ElGamal", "Cryptodome.PublicKey.ElGamal")
                    .forMethods("construct")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.GENERATION))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(Map.of("algorithm", "ElGamal")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    private static final Supplier<List<IDetectionRule<Tree>>> RSA_RULES =
            Memoize.of(PythonCryptoPublicKey::buildRSARules);

    @Nonnull
    public static List<IDetectionRule<Tree>> RSARules() {
        return RSA_RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRSARules() {
        return List.of(RSA_CONSTRUCT, RSA_GENERATE, RSA_PUBLIC_KEY);
    }

    @Nonnull
    private static final Supplier<List<IDetectionRule<Tree>>> DSA_RULES =
            Memoize.of(PythonCryptoPublicKey::buildDSARules);

    @Nonnull
    public static List<IDetectionRule<Tree>> DSARules() {
        return DSA_RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildDSARules() {
        return List.of(DSA_CONSTRUCT, DSA_GENERATE, DSA_PUBLIC_KEY);
    }

    @Nonnull
    private static final Supplier<List<IDetectionRule<Tree>>> ECC_RULES =
            Memoize.of(PythonCryptoPublicKey::buildECCRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> ECCRules() {
        return ECC_RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildECCRules() {
        return List.of(ECC_CONSTRUCT, ECC_GENERATE, ECC_IMPORT, ECC_PUBLIC_KEY);
    }

    @Nonnull
    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(PythonCryptoPublicKey::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(ELGAMAL_CONSTRUCT, ELGAMAL_GENERATE);
    }
}
