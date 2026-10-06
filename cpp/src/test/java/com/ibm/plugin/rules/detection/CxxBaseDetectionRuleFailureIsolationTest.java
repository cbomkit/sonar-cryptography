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
package com.ibm.plugin.rules.detection;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.language.ILanguageTranslation;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.CxxAggregator;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.translation.reorganizer.CxxReorganizerRules;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.utils.CxxAstNodeHelper;

/**
 * A failure while analyzing one file is logged and does not stop the analysis of the files that
 * follow it in the same scan.
 */
class CxxBaseDetectionRuleFailureIsolationTest {

    @AfterEach
    void resetSharedState() {
        CxxAggregator.reset();
    }

    @Test
    void aFailureInOneFileDoesNotStopTheNextFile() {
        final List<IDetectionRule<AstNode>> rules = new ArrayList<>();
        rules.add(new FailingDetectionRule());
        rules.addAll(CxxDetectionRules.rules());

        CxxVerifier.verifyFiles(
                List.of(
                        "rules/detection/isolation/CxxFailingFileTestFile.cc",
                        "rules/detection/isolation/CxxFileAfterFailingFileTestFile.cc"),
                new InventoryRule(rules));

        assertThat(CxxAggregator.getDetectedNodes())
                .extracting(INode::asString)
                .containsExactly("SHA-256");
    }

    @Test
    void aFileThatCannotBeParsedDoesNotStopTheNextFile() {
        CxxVerifier.verifyFiles(
                List.of(
                        "rules/detection/isolation/CxxUnparsableFileTestFile.cc",
                        "rules/detection/isolation/CxxFileAfterFailingFileTestFile.cc"),
                new InventoryRule(CxxDetectionRules.rules()));

        assertThat(CxxAggregator.getDetectedNodes())
                .extracting(INode::asString)
                .containsExactly("SHA-256");
    }

    /** An inventory rule running the given detection rules. */
    private static final class InventoryRule extends CxxBaseDetectionRule {
        InventoryRule(@Nonnull List<IDetectionRule<AstNode>> detectionRules) {
            super(true, detectionRules, CxxReorganizerRules.rules());
        }
    }

    /** A rule that fails on every call of a function named {@code explode}. */
    private static final class FailingDetectionRule implements IDetectionRule<AstNode> {
        @Override
        public boolean is(@Nonnull Class<? extends IDetectionRule> kind) {
            return false;
        }

        @Override
        public boolean match(
                @Nonnull AstNode expression, @Nonnull ILanguageTranslation<AstNode> translation) {
            if (CxxAstNodeHelper.isFunctionCall(expression)
                    && "explode".equals(CxxAstNodeHelper.getFunctionCallName(expression))) {
                throw new IllegalStateException("rule failure");
            }
            return false;
        }

        @Override
        public boolean shouldMatchExactTypes() {
            return false;
        }

        @Nonnull
        @Override
        public IDetectionContext detectionValueContext() {
            throw new UnsupportedOperationException();
        }

        @Nonnull
        @Override
        public IBundle bundle() {
            throw new UnsupportedOperationException();
        }

        @Nonnull
        @Override
        public List<IDetectionRule<AstNode>> nextDetectionRules() {
            return List.of();
        }
    }
}
