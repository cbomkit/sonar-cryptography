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

import com.ibm.common.IObserver;
import com.ibm.engine.callstack.CallContext;
import com.ibm.engine.callstack.CallContextStats;
import com.ibm.engine.callstack.CallStackAgent;
import com.ibm.engine.hooks.HookDetectionObservable;
import com.ibm.engine.hooks.HookRepository;
import com.ibm.engine.hooks.IHook;
import com.ibm.engine.hooks.IHookDetectionObserver;
import com.ibm.engine.language.ILanguageSupport;
import com.ibm.engine.language.IScanContext;
import javax.annotation.Nonnull;
import org.sonar.api.batch.fs.InputFile;

public class Handler<R, T, S, P> {
    @Nonnull private final ILanguageSupport<R, T, S, P> languageSupport;
    @Nonnull private final CallStackAgent<R, T, S, P> callStackAgent;
    @Nonnull private final HookRepository<R, T, S, P> hookRepository;
    @Nonnull private final HookDetectionObservable<R, T, S, P> hookDetectionObservable;

    public Handler(@Nonnull ILanguageSupport<R, T, S, P> languageSupport) {
        this.languageSupport = languageSupport;
        this.callStackAgent = new CallStackAgent<>(languageSupport);
        this.hookDetectionObservable = new HookDetectionObservable<>(this);
        this.hookRepository = new HookRepository<>(this);
    }

    @Nonnull
    public ILanguageSupport<R, T, S, P> getLanguageSupport() {
        return languageSupport;
    }

    public void addCallToCallStack(@Nonnull T tree, @Nonnull IScanContext<R, T> scanContext) {
        this.callStackAgent.addCall(tree, scanContext);
    }

    public void onNewHookSubscription(
            @Nonnull IHook<R, T, S, P> hook,
            @Nonnull IHookDetectionObserver<R, T, S, P> hookDetectionObserver) {
        this.callStackAgent.onNewHookSubscription(hook, hookDetectionObserver);
    }

    public boolean addHookToHookRepository(@Nonnull IHook<R, T, S, P> hook) {
        return this.hookRepository.add(hook);
    }

    public boolean deleteHookToHookRepository(@Nonnull IHook<R, T, S, P> hook) {
        return this.hookRepository.delete(hook);
    }

    public void subscribeToHookDetectionObservable(
            @Nonnull IHook<R, T, S, P> hook, @Nonnull IHookDetectionObserver<R, T, S, P> listener) {
        this.hookDetectionObservable.subscribe(hook, listener);
    }

    public void unsubscribeFormHookDetectionObservable(
            @Nonnull IHook<R, T, S, P> hook, @Nonnull IHookDetectionObserver<R, T, S, P> listener) {
        this.hookDetectionObservable.unsubscribe(hook, listener);
    }

    public void notifyAllHookDetectionObservers(
            @Nonnull CallContext<R, T> callContext, @Nonnull IHook<R, T, S, P> hook) {
        this.hookDetectionObservable.notify(callContext, hook);
    }

    public void addRecordedCall(@Nonnull CallContext<R, T> recordedCall) {
        this.callStackAgent.add(recordedCall);
    }

    public void detachCallsForFile(@Nonnull InputFile inputFile) {
        this.callStackAgent.detachCallsForFile(inputFile);
    }

    @Nonnull
    public CallContextStats callContextStats() {
        return this.callStackAgent.callContextStats();
    }

    public void subscribeToCallStackAgent(@Nonnull IObserver<CallContext<R, T>> listener) {
        this.callStackAgent.subscribe(listener);
    }

    public void unsubscribeToCallStackAgent(@Nonnull IObserver<CallContext<R, T>> listener) {
        this.callStackAgent.unsubscribe(listener);
    }

    public void notifyAllCallStackAgentObservers(@Nonnull CallContext<R, T> callContext) {
        this.callStackAgent.notify(callContext);
    }
}
