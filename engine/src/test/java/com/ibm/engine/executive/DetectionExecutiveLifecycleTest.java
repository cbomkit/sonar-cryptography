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
package com.ibm.engine.executive;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;

import com.ibm.engine.detection.Handler;
import com.ibm.engine.language.IScanContext;
import com.ibm.engine.rule.IDetectionRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DetectionExecutiveLifecycleTest {

    private DetectionExecutive<Object, Object, Object, Object> executive;

    @SuppressWarnings("unchecked")
    @BeforeEach
    void setUp() {
        IDetectionRule<Object> detectionRule = mock(IDetectionRule.class);
        IScanContext<Object, Object> scanContext = mock(IScanContext.class);
        Handler<Object, Object, Object, Object> handler = mock(Handler.class);
        executive = new DetectionExecutive<>(new Object(), detectionRule, scanContext, handler);
    }

    @Test
    void hasDeferredHooks_falseByDefault() {
        assertThat(executive.hasDeferredHooks()).isFalse();
    }

    @Test
    void onDeferredHookRegistration_setsDeferredFlagToTrue() {
        executive.onDeferredHookRegistration();

        assertThat(executive.hasDeferredHooks()).isTrue();
    }

    @Test
    void onDeferredHookRegistration_calledMultipleTimes_remainsTrue() {
        executive.onDeferredHookRegistration();
        executive.onDeferredHookRegistration();

        assertThat(executive.hasDeferredHooks()).isTrue();
    }

    @Test
    void isReleased_falseInitially() {
        assertThat(executive.isReleased()).isFalse();
    }

    @Test
    void releaseDeferredResources_setsIsReleasedTrue() {
        executive.releaseDeferredResources();

        assertThat(executive.isReleased()).isTrue();
    }

    @Test
    void releaseDeferredResources_isIdempotent() {
        assertThatCode(
                        () -> {
                            executive.releaseDeferredResources();
                            executive.releaseDeferredResources();
                        })
                .doesNotThrowAnyException();

        assertThat(executive.isReleased()).isTrue();
    }

    @Test
    void hasDeferredHooks_doesNotImplyReleased() {
        executive.onDeferredHookRegistration();

        assertThat(executive.hasDeferredHooks()).isTrue();
        assertThat(executive.isReleased()).isFalse();
    }

    @Test
    void releaseDeferredResources_doesNotClearDeferredFlag() {
        executive.onDeferredHookRegistration();
        executive.releaseDeferredResources();

        // released, but the deferred flag records what happened during the executive's lifetime
        assertThat(executive.hasDeferredHooks()).isTrue();
        assertThat(executive.isReleased()).isTrue();
    }
}
