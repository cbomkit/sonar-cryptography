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
package com.ibm.engine.callstack;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.EnumMatcher;
import com.ibm.engine.detection.IBaseMethodVisitorFactory;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.IType;
import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.executive.DetectionExecutive;
import com.ibm.engine.language.ILanguageSupport;
import com.ibm.engine.language.ILanguageTranslation;
import com.ibm.engine.language.IScanContext;
import com.ibm.engine.rule.IDetectionRule;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

/**
 * A single call node is visited once per detection rule ({@code CxxDetectionEngine}/{@code
 * JavaDetectionEngine}'s {@code run} is invoked once per rule for the same tree), so {@code
 * recordCall} calls {@link CallStackAgent#add} once per rule for the same node too. {@link
 * CallStackAgent#isRecorded} lets a caller check, before doing any expensive work, whether an
 * earlier call already added that same node - this test verifies that check reflects {@link
 * CallStackAgent#add}'s own dedup key and tree-identity check exactly.
 */
class CallStackAgentTest {

    /** A tree stand-in with its own identity, distinct from its (possibly shared) method name. */
    private record CallSite(String methodName, int siteId) {}

    @Test
    void isRecordedIsFalseBeforeTheFirstAddForATree() {
        CallStackAgent<Object, CallSite, Object, Object> agent =
                new CallStackAgent<>(fakeLanguageSupport());

        assertThat(agent.isRecorded(new CallSite("EVP_EncryptInit_ex", 1))).isFalse();
    }

    @Test
    void isRecordedIsTrueAfterTheFirstAddForThatTree() {
        CallStackAgent<Object, CallSite, Object, Object> agent =
                new CallStackAgent<>(fakeLanguageSupport());
        CallSite tree = new CallSite("EVP_EncryptInit_ex", 1);

        agent.add(new RetainedCall<>(tree, fakeScanContext(), null));

        assertThat(agent.isRecorded(tree)).isTrue();
    }

    @Test
    void isRecordedStaysTrueAcrossRepeatedAddsForTheSameTree_simulatingOneRulePerCallNode() {
        // Mirrors production: run() is invoked once per detection rule for the same call node, so
        // recordCall (and its handler.addRecordedCall -> CallStackAgent.add) is called once per
        // rule too. isRecorded must reflect the very first add so every later rule's pass can skip
        // rebuilding the detached call.
        CallStackAgent<Object, CallSite, Object, Object> agent =
                new CallStackAgent<>(fakeLanguageSupport());
        CallSite tree = new CallSite("EVP_EncryptInit_ex", 1);

        for (int rule = 0; rule < 545; rule++) {
            assertThat(agent.isRecorded(tree)).isEqualTo(rule > 0);
            agent.add(new RetainedCall<>(tree, fakeScanContext(), null));
        }

        assertThat(agent.isRecorded(tree)).isTrue();
    }

    @Test
    void isRecordedDistinguishesDifferentTreesWithTheSameMethodName() {
        // Two distinct call sites that invoke the same method name: both hash to the same bucket
        // (keyed by method name), so isRecorded must fall back to tree identity/equality within
        // that bucket rather than treating the bucket's mere existence as "recorded".
        CallStackAgent<Object, CallSite, Object, Object> agent =
                new CallStackAgent<>(fakeLanguageSupport());
        CallSite firstCallSite = new CallSite("EVP_EncryptInit_ex", 1);
        CallSite secondCallSite = new CallSite("EVP_EncryptInit_ex", 2);

        agent.add(new RetainedCall<>(firstCallSite, fakeScanContext(), null));

        assertThat(agent.isRecorded(firstCallSite)).isTrue();
        assertThat(agent.isRecorded(secondCallSite)).isFalse();
    }

    @SuppressWarnings("unchecked")
    private static IScanContext<Object, CallSite> fakeScanContext() {
        return Mockito.mock(IScanContext.class);
    }

    /**
     * A minimal {@link ILanguageSupport} whose {@code T} is {@link CallSite}: only {@link
     * ILanguageSupport#translation()} is ever called by {@link CallStackAgent#add}/{@link
     * CallStackAgent#isRecorded}, via {@link ILanguageTranslation#getMethodName}, so every other
     * method throws if reached - which would mean this test's understanding of {@link
     * CallStackAgent}'s dependencies is wrong.
     */
    private static ILanguageSupport<Object, CallSite, Object, Object> fakeLanguageSupport() {
        return new ILanguageSupport<>() {
            @Override
            public ILanguageTranslation<CallSite> translation() {
                return new ILanguageTranslation<>() {
                    @Override
                    public Optional<String> getMethodName(
                            MatchContext matchContext, CallSite methodInvocation) {
                        return Optional.of(methodInvocation.methodName());
                    }

                    @Override
                    public Optional<IType> getInvokedObjectTypeString(
                            MatchContext matchContext, CallSite methodInvocation) {
                        throw new UnsupportedOperationException();
                    }

                    @Override
                    public Optional<IType> getMethodReturnTypeString(
                            MatchContext matchContext, CallSite methodInvocation) {
                        throw new UnsupportedOperationException();
                    }

                    @Override
                    public List<IType> getMethodParameterTypes(
                            MatchContext matchContext, CallSite methodInvocation) {
                        throw new UnsupportedOperationException();
                    }

                    @Override
                    public Optional<String> resolveIdentifierAsString(
                            MatchContext matchContext, CallSite identifier) {
                        throw new UnsupportedOperationException();
                    }

                    @Override
                    public Optional<String> getEnumIdentifierName(
                            MatchContext matchContext, CallSite enumConstant) {
                        throw new UnsupportedOperationException();
                    }

                    @Override
                    public Optional<String> getEnumClassName(
                            MatchContext matchContext, CallSite enumClass) {
                        return Optional.empty();
                    }
                };
            }

            @Override
            public DetectionExecutive<Object, CallSite, Object, Object> createDetectionExecutive(
                    CallSite tree,
                    IDetectionRule<CallSite> detectionRule,
                    IScanContext<Object, CallSite> scanContext) {
                throw new UnsupportedOperationException();
            }

            @Override
            public IDetectionEngine<CallSite, Object> createDetectionEngineInstance(
                    DetectionStore<Object, CallSite, Object, Object> detectionStore) {
                throw new UnsupportedOperationException();
            }

            @Override
            public IBaseMethodVisitorFactory<CallSite, Object> getBaseMethodVisitorFactory() {
                throw new UnsupportedOperationException();
            }

            @Override
            public Optional<CallSite> getEnclosingMethod(CallSite expression) {
                throw new UnsupportedOperationException();
            }

            @Override
            public MethodMatcher<CallSite> createMethodMatcherBasedOn(CallSite methodDefinition) {
                throw new UnsupportedOperationException();
            }

            @Override
            public EnumMatcher<CallSite> createSimpleEnumMatcherFor(
                    CallSite enumIdentifier, MatchContext matchContext) {
                throw new UnsupportedOperationException();
            }
        };
    }
}
