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
package com.ibm.engine.detection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;

import com.ibm.engine.executive.IStatusReporting;
import com.ibm.engine.language.IScanContext;
import com.ibm.engine.model.IAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.rule.IDetectionRule;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DetectionStoreReleaseTest {

    private IDetectionRule<Object> detectionRule;
    private IScanContext<Object, Object> scanContext;
    private Handler<Object, Object, Object, Object> handler;
    private IStatusReporting<Object, Object, Object, Object> statusReporting;
    private IValue<Object> mockValue;
    private IAction<Object> mockAction;

    private DetectionStore<Object, Object, Object, Object> store;

    @SuppressWarnings("unchecked")
    @BeforeEach
    void setUp() {
        detectionRule = mock(IDetectionRule.class);
        scanContext = mock(IScanContext.class);
        handler = mock(Handler.class);
        statusReporting = mock(IStatusReporting.class);
        mockValue = mock(IValue.class);
        mockAction = mock(IAction.class);
        store = new DetectionStore<>(0, detectionRule, scanContext, handler, statusReporting);
    }

    @Test
    void release_clearsDetectionValues() {
        store.detectionValues.put(0, new ArrayList<>(List.of(mockValue)));
        assertThat(store.getDetectionValues()).isNotEmpty();

        store.release();

        assertThat(store.getDetectionValues()).isEmpty();
    }

    @Test
    void release_clearsChildren() {
        DetectionStore<Object, Object, Object, Object> child =
                new DetectionStore<>(1, detectionRule, scanContext, handler, statusReporting);
        store.children.put(0, new ArrayList<>(List.of(child)));
        assertThat(store.getChildren()).isNotEmpty();

        store.release();

        assertThat(store.getChildren()).isEmpty();
    }

    @Test
    void release_clearsActionValue() {
        store.actionValue = mockAction;
        assertThat(store.getActionValue()).isPresent();

        store.release();

        assertThat(store.getActionValue()).isEmpty();
    }

    @Test
    void release_onEmptyStore_doesNotThrow() {
        assertThatCode(() -> store.release()).doesNotThrowAnyException();
        assertThat(store.getDetectionValues()).isEmpty();
        assertThat(store.getChildren()).isEmpty();
    }

    @Test
    void release_clearsChildDetectionValues() {
        DetectionStore<Object, Object, Object, Object> child =
                new DetectionStore<>(1, detectionRule, scanContext, handler, statusReporting);
        child.detectionValues.put(0, new ArrayList<>(List.of(mockValue)));
        store.children.put(0, new ArrayList<>(List.of(child)));

        store.release();

        assertThat(store.getChildren()).isEmpty();
        assertThat(child.getDetectionValues()).isEmpty();
    }

    @Test
    void release_clearsDeepNestedChildren() {
        DetectionStore<Object, Object, Object, Object> child =
                new DetectionStore<>(1, detectionRule, scanContext, handler, statusReporting);
        DetectionStore<Object, Object, Object, Object> grandchild =
                new DetectionStore<>(2, detectionRule, scanContext, handler, statusReporting);

        grandchild.detectionValues.put(0, new ArrayList<>(List.of(mockValue)));
        child.children.put(0, new ArrayList<>(List.of(grandchild)));
        store.children.put(0, new ArrayList<>(List.of(child)));

        store.release();

        assertThat(store.getChildren()).isEmpty();
        assertThat(child.getChildren()).isEmpty();
        assertThat(grandchild.getDetectionValues()).isEmpty();
    }

    @Test
    void release_handlesDeepChainsWithoutRecursiveTraversal() {
        DetectionStore<Object, Object, Object, Object> current = store;
        List<DetectionStore<Object, Object, Object, Object>> chain = new ArrayList<>();
        chain.add(store);

        for (int i = 1; i <= 20_000; i++) {
            DetectionStore<Object, Object, Object, Object> child =
                    new DetectionStore<>(i, detectionRule, scanContext, handler, statusReporting);
            child.detectionValues.put(0, new ArrayList<>(List.of(mockValue)));
            current.children.put(0, new ArrayList<>(List.of(child)));
            chain.add(child);
            current = child;
        }

        assertThatCode(() -> store.release()).doesNotThrowAnyException();

        assertThat(chain)
                .allSatisfy(
                        releasedStore -> {
                            assertThat(releasedStore.getDetectionValues()).isEmpty();
                            assertThat(releasedStore.getChildren()).isEmpty();
                        });
    }

    @Test
    void release_multipleValuesAndChildren_allCleared() {
        store.detectionValues.put(0, new ArrayList<>(List.of(mockValue)));
        store.detectionValues.put(1, new ArrayList<>(List.of(mockValue)));
        store.actionValue = mockAction;

        DetectionStore<Object, Object, Object, Object> child1 =
                new DetectionStore<>(1, detectionRule, scanContext, handler, statusReporting);
        DetectionStore<Object, Object, Object, Object> child2 =
                new DetectionStore<>(1, detectionRule, scanContext, handler, statusReporting);
        store.children.put(0, new ArrayList<>(List.of(child1)));
        store.children.put(1, new ArrayList<>(List.of(child2)));

        store.release();

        assertThat(store.getDetectionValues()).isEmpty();
        assertThat(store.getChildren()).isEmpty();
        assertThat(store.getActionValue()).isEmpty();
    }
}
