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
package com.ibm.plugin.rules.detection.bc.signer;

import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.bc.digest.BcDigests;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcSM2Signer {

    private BcSM2Signer() {
        // nothing
    }

    private static final String CLASS_NAME = "SM2Signer";

    private static final IDetectionRule<Tree> CONSTRUCTOR_1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.crypto.signers." + CLASS_NAME)
                    .forConstructor()
                    .shouldBeDetectedAs(new ValueActionFactory<>(CLASS_NAME))
                    .withoutParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "Bc")
                    .withDependingDetectionRules(BcSignerInit.rules());

    private static final IDetectionRule<Tree> CONSTRUCTOR_2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.crypto.signers." + CLASS_NAME)
                    .forConstructor()
                    .shouldBeDetectedAs(new ValueActionFactory<>(CLASS_NAME))
                    .withMethodParameter("org.bouncycastle.crypto.Digest")
                    .addDependingDetectionRules(BcDigests.rules())
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "Bc")
                    .withDependingDetectionRules(BcSignerInit.rules());

    private static final IDetectionRule<Tree> CONSTRUCTOR_3 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.crypto.signers." + CLASS_NAME)
                    .forConstructor()
                    .shouldBeDetectedAs(new ValueActionFactory<>(CLASS_NAME))
                    .withMethodParameter("org.bouncycastle.crypto.signers.DSAEncoding")
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "Bc")
                    .withDependingDetectionRules(BcSignerInit.rules());

    private static final IDetectionRule<Tree> CONSTRUCTOR_4 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.crypto.signers." + CLASS_NAME)
                    .forConstructor()
                    .shouldBeDetectedAs(new ValueActionFactory<>(CLASS_NAME))
                    .withMethodParameter("org.bouncycastle.crypto.signers.DSAEncoding")
                    .withMethodParameter("org.bouncycastle.crypto.Digest")
                    .addDependingDetectionRules(BcDigests.rules())
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "Bc")
                    .withDependingDetectionRules(BcSignerInit.rules());

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(() -> List.of(CONSTRUCTOR_1, CONSTRUCTOR_2, CONSTRUCTOR_3, CONSTRUCTOR_4));

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }
}
