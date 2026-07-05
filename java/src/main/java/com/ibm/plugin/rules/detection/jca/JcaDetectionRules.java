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

import com.ibm.engine.rule.IDetectionRule;
import com.ibm.plugin.rules.detection.Memoize;
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
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JcaDetectionRules {
    private JcaDetectionRules() {
        // private
    }

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(JcaDetectionRules::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return Stream.of(
                        // cipher algorithm
                        JcaCipherGetInstance.rules().stream(),
                        // key
                        JcaKeyFactoryGetInstance.rules().stream(),
                        JcaKeyGeneratorGetInstance.rules().stream(),
                        JcaKeyPairGeneratorGetInstance.rules().stream(),
                        // secret key
                        JcaSecretKeyFactoryGetInstance.rules().stream(),
                        JcaSecretKeySpec.rules().stream(),
                        // digest
                        JcaDigest.rules().stream(),
                        // signature
                        JcaSignatureGetInstance.rules().stream(),
                        // mac
                        JcaMacGetInstance.rules().stream(),
                        // algorithm
                        JcaAlgorithmParameterGeneratorGetInstance.rules().stream(),
                        // key agreement
                        JcaKeyAgreementGetInstance.rules().stream())
                .flatMap(i -> i)
                .toList();
    }
}
