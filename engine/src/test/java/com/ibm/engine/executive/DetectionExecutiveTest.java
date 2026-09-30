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
package com.ibm.engine.executive;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.Finding;
import com.ibm.engine.detection.Handler;
import com.ibm.engine.detection.MethodDetection;
import com.ibm.engine.language.IScanContext;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The findings a detection executive reports for a detection store tree. */
class DetectionExecutiveTest {

    private final IDetectionRule<String> initRule =
            new DetectionRuleBuilder<String>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Test")
                    .withoutDependingDetectionRules();

    /** Creates an object, followed to the calls made on it. */
    private final IDetectionRule<String> contextRule =
            new DetectionRuleBuilder<String>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("ctx_new")
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Test")
                    .withDependingDetectionRules(List.of(initRule));

    /** Detects a value of its own, followed to the calls made on the object it creates. */
    private final IDetectionRule<String> getInstanceRule =
            new DetectionRuleBuilder<String>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("getInstance")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Test")
                    .withDependingDetectionRules(List.of(initRule));

    /** Creates an object, not followed. */
    private final IDetectionRule<String> notFollowedRule =
            new DetectionRuleBuilder<String>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("create")
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Test")
                    .withoutDependingDetectionRules();

    @SuppressWarnings("unchecked")
    private final Handler<Object, String, Object, Object> handler =
            mock(Handler.class, RETURNS_DEEP_STUBS);

    @SuppressWarnings("unchecked")
    private final IScanContext<Object, String> scanContext = mock(IScanContext.class);

    @SuppressWarnings("unchecked")
    private final IStatusReporting<Object, String, Object, Object> statusReporting =
            mock(IStatusReporting.class);

    private final List<Finding<Object, String, Object, Object>> findings = new ArrayList<>();
    private DetectionExecutive<Object, String, Object, Object> executive;

    @BeforeEach
    void setUp() {
        executive = new DetectionExecutive<>("ctx_new()", contextRule, scanContext, handler);
        executive.subscribe(findings::add);
        executive.incrementVisitedRules();
    }

    @Test
    void storeWithValueIsOneFinding() {
        final DetectionStore<Object, String, Object, Object> init = matched(initRule, "init()");

        executive.emitFinding(init);

        assertThat(findings).extracting(Finding::detectionStore).containsExactly(init);
    }

    @Test
    void storeWithoutValueReportsTheCallsMadeOnItsObjectTogether() {
        final DetectionStore<Object, String, Object, Object> context =
                matched(contextRule, "ctx_new()");
        final DetectionStore<Object, String, Object, Object> init = matched(initRule, "init()");
        context.attach(init);

        executive.emitFinding(context);

        assertThat(findings).extracting(Finding::detectionStore).containsExactly(context);
    }

    @Test
    void storeWithoutValueReportsTheArgumentsOfItsCallAndTheCallsMadeOnItsObjectTogether() {
        final DetectionStore<Object, String, Object, Object> context =
                matched(contextRule, "ctx_new(cipher())");
        final DetectionStore<Object, String, Object, Object> argument = matched(initRule, "a()");
        final DetectionStore<Object, String, Object, Object> operation = matched(initRule, "b()");
        context.attach(0, argument);
        context.attach(operation);

        executive.emitFinding(context);

        assertThat(findings).extracting(Finding::detectionStore).containsExactly(context);
    }

    @Test
    void storeWhoseOwnValueWasFoundElsewhereReportsTheValuesBelowItSeparately() {
        // getInstance(algorithm()): the value of the call is resolved in the called function
        final DetectionStore<Object, String, Object, Object> getInstance = store(getInstanceRule);
        final DetectionStore<Object, String, Object, Object> ownValue =
                matched(getInstanceRule, "algorithm()");
        final DetectionStore<Object, String, Object, Object> operation = matched(initRule, "b()");
        getInstance.attach(0, ownValue);
        getInstance.attach(operation);

        executive.emitFinding(getInstance);

        assertThat(findings)
                .extracting(Finding::detectionStore)
                .containsExactly(operation, ownValue);
    }

    @Test
    void storeWithoutValueNotFollowedReportsTheValuesBelowItSeparately() {
        final DetectionStore<Object, String, Object, Object> created =
                matched(notFollowedRule, "create()");
        final DetectionStore<Object, String, Object, Object> first = matched(initRule, "a()");
        final DetectionStore<Object, String, Object, Object> second = matched(initRule, "b()");
        created.attach(0, first);
        created.attach(1, second);

        executive.emitFinding(created);

        assertThat(findings).extracting(Finding::detectionStore).containsExactly(first, second);
    }

    @Test
    void storeWithoutAnyValueIsNoFinding() {
        final DetectionStore<Object, String, Object, Object> context =
                matched(contextRule, "ctx_new()");
        context.attach(matched(contextRule, "ctx_new()"));

        executive.emitFinding(context);

        assertThat(findings).isEmpty();
    }

    @Test
    void noFindingBeforeEveryRuleIsVisited() {
        executive.addAdditionalExpectedRuleVisits(1);

        executive.emitFinding(matched(initRule, "init()"));

        assertThat(findings).isEmpty();
    }

    @Nonnull
    private DetectionStore<Object, String, Object, Object> matched(
            @Nonnull IDetectionRule<String> rule, @Nonnull String call) {
        final DetectionStore<Object, String, Object, Object> store = store(rule);
        store.onReceivingNewDetection(new MethodDetection<>(call, null));
        return store;
    }

    @Nonnull
    private DetectionStore<Object, String, Object, Object> store(
            @Nonnull IDetectionRule<String> rule) {
        return new DetectionStore<>(0, rule, scanContext, handler, statusReporting);
    }
}
