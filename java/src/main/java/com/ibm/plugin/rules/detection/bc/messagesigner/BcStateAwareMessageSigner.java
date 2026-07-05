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
package com.ibm.plugin.rules.detection.bc.messagesigner;

import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.bc.BouncyCastleInfoMap;
import com.ibm.plugin.rules.detection.bc.digest.BcDigests;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcStateAwareMessageSigner {
    private BcStateAwareMessageSigner() {
        // nothing
    }

    private static BouncyCastleInfoMap infoMap = new BouncyCastleInfoMap();

    static {
        /*
         * List of classes implementing StateAwareMessageSigner with an empty constructor
         */
        infoMap.putKey("XMSSMTSigner").putType("org.bouncycastle.pqc.crypto.xmss.");
        infoMap.putKey("XMSSSigner").putType("org.bouncycastle.pqc.crypto.xmss.");
    }

    private static @Nonnull List<IDetectionRule<Tree>> simpleConstructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        for (Map.Entry<String, BouncyCastleInfoMap.Info> entry : infoMap.entrySet()) {
            String signer = entry.getKey();
            String type = entry.getValue().getType();
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes(type + signer)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(signer))
                            .withoutParameters()
                            .buildForContext(new SignatureContext(Map.of("kind", "MESSAGE_SIGNER")))
                            .inBundle(() -> "Bc")
                            .withDependingDetectionRules(BcMessageSignerInit.rules()));
        }
        return constructorsList;
    }

    private static @Nonnull List<IDetectionRule<Tree>> specialConstructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes(
                                "org.bouncycastle.pqc.legacy.crypto.gmss.GMSSStateAwareSigner")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("GMSSStateAwareSigner"))
                        .withMethodParameter("org.bouncycastle.crypto.Digest")
                        .addDependingDetectionRules(BcDigests.rules())
                        .buildForContext(new SignatureContext(Map.of("kind", "MESSAGE_SIGNER")))
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcMessageSignerInit.rules()));

        return constructorsList;
    }

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(
                    () ->
                            Stream.of(simpleConstructors().stream(), specialConstructors().stream())
                                    .flatMap(i -> i)
                                    .toList());

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }
}
