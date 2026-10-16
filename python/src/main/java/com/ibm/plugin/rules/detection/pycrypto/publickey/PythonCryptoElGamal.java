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
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

// Only the ElGamal rules are registered as top-level detection rules. The documentation
// describes them as obsolete keys. Pycryptodome does not provide a higher-level method
// (encryption, signature) based on ElGamal keys.
@SuppressWarnings("java:S1192")
public final class PythonCryptoElGamal extends DetectionRuleSet<Tree> {

    private PythonCryptoElGamal() {
        // private
    }

    // ElGamal
    private static final IDetectionRule<Tree> ELGAMAL_GENERATE =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.PublicKey.ElGamal", "Cryptodome.PublicKey.ElGamal")
                    .forMethods("generate")
                    //     .shouldBeDetectedAs(
                    //             new KeyActionFactory<>(KeyAction.Action.PRIVATE_KEY_GENERATION))
                    .withNamedMethodParameter("bits", "int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .asChildOfParameterWithId(-1)
                    .withNamedMethodParameter("randfunc", ANY)
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
    @Override
    protected List<IDetectionRule<Tree>> buildRules() {
        return List.of(ELGAMAL_CONSTRUCT, ELGAMAL_GENERATE);
    }
}
