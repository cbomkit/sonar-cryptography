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

import com.ibm.engine.detection.DetectionStore;
import javax.annotation.Nonnull;

public interface IStatusReporting<R, T, S, P> {
    void emitFinding();

    void emitFinding(@Nonnull DetectionStore<R, T, S, P> rootDetectionStore);

    void incrementVisitedRules();

    void addAdditionalExpectedRuleVisits(int number);

    /**
     * Called when a detection store registers a hook whose invocation may fire after the current
     * rule-visit cycle has completed.
     *
     * @apiNote This method is triggered by {@link
     *     com.ibm.engine.detection.DetectionStore#onNewHookRegistration} the first time a deferred
     *     hook is registered on a given scan node. It signals that at least one pending hook
     *     invocation may still emit findings after {@code emitFinding()} would otherwise release
     *     resources.
     * @implSpec Implementations that manage a release lifecycle <em>must</em> set an internal flag
     *     to suppress eager resource cleanup until all deferred hook invocations have completed.
     *     For example:
     *     <pre>{@code
     * @Override
     * public void onDeferredHookRegistration() {
     *     this.deferredHookRegistered = true;
     *     // emitFinding() will now skip releaseResources() and instead wait
     *     // for an explicit releaseDeferredResources() call from the scan driver.
     * }
     * }</pre>
     *     Failing to suppress the release will cause the detection-store tree to be cleared before
     *     the pending hook findings are emitted, silently dropping detections.
     * @implNote The default no-op is intentional. Language-module status reporters written before
     *     this method was introduced do not track deferred-hook lifecycles and remain fully
     *     source-compatible without any code changes.
     * @since PR #417
     */
    default void onDeferredHookRegistration() {
        // Optional lifecycle callback for deferred hook-based findings.
    }
}
