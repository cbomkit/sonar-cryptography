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
package com.ibm.plugin.rules.detection.jca;

import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
import com.ibm.plugin.rules.detection.jca.algorithmparametergenerator.JcaAlgorithmParameterGeneratorGetInstance;
import com.ibm.plugin.rules.detection.jca.cipher.JcaCipherGetInstance;
import com.ibm.plugin.rules.detection.jca.digest.JcaDigest;
import com.ibm.plugin.rules.detection.jca.keyagreement.JcaKeyAgreementGetInstance;
import com.ibm.plugin.rules.detection.jca.keyfactory.JcaKeyFactoryGetInstance;
import com.ibm.plugin.rules.detection.jca.keyfactory.JcaSecretKeyFactoryGetInstance;
import com.ibm.plugin.rules.detection.jca.keygenerator.JcaKeyGeneratorGetInstance;
import com.ibm.plugin.rules.detection.jca.keygenerator.JcaKeyPairGeneratorGetInstance;
import com.ibm.plugin.rules.detection.jca.keyspec.JcaSecretKeySpec;
import com.ibm.plugin.rules.detection.jca.mac.JcaMacGetInstance;
import com.ibm.plugin.rules.detection.jca.signature.JcaSignatureGetInstance;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JcaDetectionRules extends DetectionRuleSet<Tree> {

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules() {
        return Stream.of(
                        // cipher algorithm
                        RuleSets.rulesOf(JcaCipherGetInstance.class).stream(),
                        // key
                        RuleSets.rulesOf(JcaKeyFactoryGetInstance.class).stream(),
                        RuleSets.rulesOf(JcaKeyGeneratorGetInstance.class).stream(),
                        RuleSets.rulesOf(JcaKeyPairGeneratorGetInstance.class).stream(),
                        // secret key
                        RuleSets.rulesOf(JcaSecretKeyFactoryGetInstance.class).stream(),
                        RuleSets.rulesOf(JcaSecretKeySpec.class).stream(),
                        // digest
                        RuleSets.rulesOf(JcaDigest.class).stream(),
                        // signature
                        RuleSets.rulesOf(JcaSignatureGetInstance.class).stream(),
                        // mac
                        RuleSets.rulesOf(JcaMacGetInstance.class).stream(),
                        // algorithm
                        RuleSets.rulesOf(JcaAlgorithmParameterGeneratorGetInstance.class).stream(),
                        // key agreement
                        RuleSets.rulesOf(JcaKeyAgreementGetInstance.class).stream())
                .flatMap(i -> i)
                .toList();
    }
}
