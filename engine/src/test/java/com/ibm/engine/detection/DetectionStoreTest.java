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
package com.ibm.engine.detection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;

import com.ibm.engine.executive.IStatusReporting;
import com.ibm.engine.language.IScanContext;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/** The calls a detection store records, and the tree a finding is reported on. */
class DetectionStoreTest {

    private final IDetectionRule<String> contextRule =
            new DetectionRuleBuilder<String>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("ctx_new")
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Test")
                    .withoutDependingDetectionRules();

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

    @SuppressWarnings("unchecked")
    private final Handler<Object, String, Object, Object> handler =
            mock(Handler.class, RETURNS_DEEP_STUBS);

    @SuppressWarnings("unchecked")
    private final IScanContext<Object, String> scanContext = mock(IScanContext.class);

    @SuppressWarnings("unchecked")
    private final IStatusReporting<Object, String, Object, Object> statusReporting =
            mock(IStatusReporting.class);

    @Test
    void recordsEveryCallTheRuleMatchesOnce() {
        final String first = "init(ctx, cipher)";
        final String second = "init(ctx, NULL)";
        final DetectionStore<Object, String, Object, Object> store = store(initRule);

        store.onReceivingNewDetection(new MethodDetection<>(first, null));
        store.onReceivingNewDetection(new MethodDetection<>(second, null));
        store.onReceivingNewDetection(new MethodDetection<>(first, null));

        assertThat(store.getDetectedExpressions()).containsExactly(first, second);
        assertThat(store.getDetectedExpression()).contains(first);
    }

    @Test
    void recordsNoCallBeforeAMatch() {
        final DetectionStore<Object, String, Object, Object> store = store(initRule);

        assertThat(store.getDetectedExpressions()).isEmpty();
        assertThat(store.getDetectedExpression()).isEmpty();
    }

    @Test
    void findingIsReportedOnItsFirstValue() {
        final DetectionStore<Object, String, Object, Object> store = store(initRule);
        store.onReceivingNewDetection(new MethodDetection<>("init()", "init"));

        assertThat(new Finding<>(store).getMarkerTree()).isEqualTo("init");
    }

    @Test
    void findingWithoutValueIsReportedOnTheCallItMatched() {
        final DetectionStore<Object, String, Object, Object> context = store(contextRule);
        context.onReceivingNewDetection(new MethodDetection<>("ctx_new()", null));
        final DetectionStore<Object, String, Object, Object> init = store(initRule);
        init.onReceivingNewDetection(new MethodDetection<>("init()", null));
        context.attach(init);

        assertThat(new Finding<>(context).getMarkerTree()).isEqualTo("ctx_new()");
    }

    @Test
    void findingWithoutValueOrCallIsReportedOnTheFirstValueBelowIt() {
        final DetectionStore<Object, String, Object, Object> root = store(contextRule);
        final DetectionStore<Object, String, Object, Object> empty = store(contextRule);
        final DetectionStore<Object, String, Object, Object> init = store(initRule);
        init.onReceivingNewDetection(new MethodDetection<>("init()", null));
        empty.attach(init);
        root.attach(empty);

        assertThat(new Finding<>(root).getMarkerTree()).isEqualTo("init()");
    }

    @Nonnull
    private DetectionStore<Object, String, Object, Object> store(
            @Nonnull IDetectionRule<String> rule) {
        return new DetectionStore<>(0, rule, scanContext, handler, statusReporting);
    }
}
