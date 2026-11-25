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
package com.ibm.plugin.rules.detection.nodecrypto;

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.javascript.tree.JavaScriptTree;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for the methods called on the {@code Hash} object that {@code
 * crypto.createHash()} returns. They are the <em>dependent</em> rules of {@link NodeCryptoHash}:
 * they only fire on calls whose receiver is the variable the {@code createHash} result was assigned
 * to, which for an inline chain is the converter's synthetic chain variable.
 */
public final class NodeCryptoHashMethods extends DetectionRuleSet<JavaScriptTree> {

    private static final IDetectionRule<JavaScriptTree> UPDATE =
            new DetectionRuleBuilder<JavaScriptTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("update")
                    .shouldBeDetectedAs(new ValueActionFactory<>("update"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> NodeCryptoHash.BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<JavaScriptTree> DIGEST =
            new DetectionRuleBuilder<JavaScriptTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("digest")
                    .shouldBeDetectedAs(new ValueActionFactory<>("digest"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> NodeCryptoHash.BUNDLE)
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<JavaScriptTree>> buildRules() {
        return List.of(UPDATE, DIGEST);
    }
}
