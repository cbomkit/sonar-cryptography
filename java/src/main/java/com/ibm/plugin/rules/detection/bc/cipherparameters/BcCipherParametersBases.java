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
package com.ibm.plugin.rules.detection.bc.cipherparameters;

import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcCipherParametersBases extends DetectionRuleSet<Tree> {

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules() {
        return Stream.of(
                        RuleSets.rulesOf(BcAEADParameters.class).stream(),
                        RuleSets.rulesOf(BcCCMParameters.class).stream(),
                        RuleSets.rulesOf(BcCramerShoupParameters.class).stream(),
                        RuleSets.rulesOf(BcGMSSParameters.class).stream(),
                        RuleSets.rulesOf(BcIESParameters.class).stream(),
                        RuleSets.rulesOf(BcKeyParameter.class).stream(),
                        RuleSets.rulesOf(BcNTRUEncryptionParameters.class).stream(),
                        RuleSets.rulesOf(BcNTRUSigningPrivateKeyParameters.class).stream(),
                        RuleSets.rulesOf(BcNTRUSigningPublicKeyParameters.class).stream(),
                        RuleSets.rulesOf(BcSABERParameters.class).stream(),
                        RuleSets.rulesOf(BcMLKEMKeyParameters.class).stream(),
                        RuleSets.rulesOf(BcMLKEMPrivateKeyParameters.class).stream(),
                        RuleSets.rulesOf(BcMLKEMPublicKeyParameters.class).stream(),
                        RuleSets.rulesOf(BcMLDSAKeyParameters.class).stream(),
                        RuleSets.rulesOf(BcMLDSAPrivateKeyParameters.class).stream(),
                        RuleSets.rulesOf(BcMLDSAPublicKeyParameters.class).stream())
                .flatMap(i -> i)
                .toList();
    }
}
