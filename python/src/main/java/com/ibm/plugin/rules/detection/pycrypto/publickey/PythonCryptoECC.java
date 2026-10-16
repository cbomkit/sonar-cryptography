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
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.engine.model.factory.CurveFactory;
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

// For RSA, DSA, and ECC keys there are corresponding signature or encryption schemes
// that use them as a parameter. In order the detect the key object in the context of
// these higher-level methods the corresponding rules are used as dependent rules.
@SuppressWarnings("java:S1192")
public final class PythonCryptoECC extends DetectionRuleSet<Tree> {

    private PythonCryptoECC() {
        // private
    }

    // ECC key generation
    private static final IDetectionRule<Tree> ECC_GENERATE =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.PublicKey.ECC", "Cryptodome.PublicKey.ECC")
                    .forMethods("generate")
                    // .shouldBeDetectedAs(new
                    // KeyActionFactory<>(KeyAction.Action.PRIVATE_KEY_GENERATION))
                    .withNamedMethodParameter("curve", "str")
                    .shouldBeDetectedAs(new CurveFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("randfunc", ANY)
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
                    .withNamedMethodParameter("curve", "str")
                    .shouldBeDetectedAs(new CurveFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("d", "int")
                    .withOptionalNamedMethodParameter("seed", ANY)
                    .withOptionalNamedMethodParameter("point_x", "int")
                    .withOptionalNamedMethodParameter("point_y", "int")
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

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules() {
        return List.of(ECC_CONSTRUCT, ECC_GENERATE, ECC_IMPORT, ECC_PUBLIC_KEY);
    }
}
