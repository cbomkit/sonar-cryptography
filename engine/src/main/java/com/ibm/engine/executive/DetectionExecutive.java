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

import com.ibm.common.IDomainEvent;
import com.ibm.common.IObserver;
import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.Finding;
import com.ibm.engine.detection.Handler;
import com.ibm.engine.language.IScanContext;
import com.ibm.engine.rule.IDetectionRule;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class DetectionExecutive<R, T, S, P>
        implements IStatusReporting<R, T, S, P>, IDomainEvent<Finding<R, T, S, P>> {
    @Nonnull private final List<IObserver<Finding<R, T, S, P>>> listeners = new ArrayList<>();

    @Nonnull private final DetectionStore<R, T, S, P> rootDetectionStore;
    @Nullable private T tree;
    private int expectedRuleVisits;
    private int visitedRules = 0;
    private boolean deferredHookRegistered = false;
    private boolean released = false;

    public DetectionExecutive(
            @Nonnull final T tree,
            @Nonnull final IDetectionRule<T> detectionRule,
            @Nonnull final IScanContext<R, T> scanContext,
            @Nonnull final Handler<R, T, S, P> handler) {
        this.tree = tree;
        this.expectedRuleVisits = 1;
        this.rootDetectionStore =
                new DetectionStore<>(0, detectionRule, scanContext, handler, this);
    }

    public void start() {
        try {
            this.rootDetectionStore.analyse(tree);
        } finally {
            this.tree = null;
        }
    }

    @Override
    public void emitFinding() {
        emitFinding(this.rootDetectionStore);
    }

    @Override
    public void emitFinding(@Nonnull final DetectionStore<R, T, S, P> rootDetectionStore) {
        if (this.expectedRuleVisits != this.visitedRules) {
            return;
        }
        try {
            getRootStoresWithValue(rootDetectionStore)
                    .forEach(
                            store -> {
                                final Finding<R, T, S, P> finding = new Finding<>(store);
                                this.notify(finding);
                            });
        } finally {
            if (!deferredHookRegistered) {
                releaseResources();
            }
        }
    }

    @Override
    public void incrementVisitedRules() {
        this.visitedRules += 1;
    }

    @Override
    public void addAdditionalExpectedRuleVisits(int number) {
        this.expectedRuleVisits += number;
    }

    @Override
    public void onDeferredHookRegistration() {
        this.deferredHookRegistered = true;
    }

    public boolean hasDeferredHooks() {
        return deferredHookRegistered;
    }

    public boolean isReleased() {
        return released;
    }

    public void releaseDeferredResources() {
        releaseResources();
    }

    @Nonnull
    private List<DetectionStore<R, T, S, P>> getRootStoresWithValue(
            @Nonnull DetectionStore<R, T, S, P> detectionStore) {
        if (!detectionStore.getDetectionValues().isEmpty()
                || detectionStore.getActionValue().isPresent()) {
            return List.of(detectionStore);
        }
        return detectionStore.getChildren().stream()
                .map(this::getRootStoresWithValue)
                .flatMap(Collection::stream)
                .toList();
    }

    @Override
    public void subscribe(@Nonnull IObserver<Finding<R, T, S, P>> listener) {
        this.listeners.add(listener);
    }

    @Override
    public void unsubscribe(@Nonnull IObserver<Finding<R, T, S, P>> listener) {
        this.listeners.remove(listener);
    }

    @Override
    public void notify(@Nonnull Finding<R, T, S, P> finding) {
        this.listeners.forEach(listener -> listener.update(finding));
    }

    private void releaseResources() {
        if (released) {
            return;
        }
        released = true;
        rootDetectionStore.release();
        listeners.clear();
        // Defensive null — start()'s finally already clears tree; retained here for safety if
        // releaseResources() is ever called independently in future.
        tree = null;
    }
}
