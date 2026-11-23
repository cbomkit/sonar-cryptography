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
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
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
public final class PythonCryptoDSA extends DetectionRuleSet<Tree> {

    private PythonCryptoDSA() {
        // private
    }

    // DSA generate -> private key
    private static final IDetectionRule<Tree> DSA_GENERATE =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.PublicKey.DSA", "Cryptodome.PublicKey.DSA")
                    .forMethods("generate")
                    //     .shouldBeDetectedAs(
                    //             new KeyActionFactory<>(KeyAction.Action.PRIVATE_KEY_GENERATION))
                    .withNamedMethodParameter("bits", "int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("randfunc", ANY)
                    .withOptionalNamedMethodParameter("domain", ANY)
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

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules() {
        return List.of(DSA_CONSTRUCT, DSA_GENERATE, DSA_PUBLIC_KEY);
    }
}
