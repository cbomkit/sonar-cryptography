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
package com.ibm.engine.hooks;

import com.ibm.engine.callstack.CallContext;
import com.ibm.engine.detection.Handler;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

public class HookDetectionObservable<R, T, S, P> implements IHookDetectionObservable<R, T, S, P> {
    @Nonnull
    private final Map<T, List<IHookDetectionObserver<R, T, S, P>>> listeners = new HashMap<>();

    @Nonnull private final Handler<R, T, S, P> handler;

    public HookDetectionObservable(@Nonnull Handler<R, T, S, P> handler) {
        this.handler = handler;
    }

    @Override
    public void subscribe(
            @Nonnull IHook<R, T, S, P> hook, @Nonnull IHookDetectionObserver<R, T, S, P> listener) {
        listeners.putIfAbsent(hook.hookValue(), new ArrayList<>());
        listeners.get(hook.hookValue()).add(listener);
        // look through the existing call Stack and find hook trigger
        if (listener.isRootHook()) {
            handler.onNewHookSubscription(hook, listener);
        }
    }

    @Override
    public void unsubscribe(
            @Nonnull IHook<R, T, S, P> hook, @Nonnull IHookDetectionObserver<R, T, S, P> listener) {
        listeners.get(hook.hookValue()).remove(listener);
    }

    @Override
    public void notify(@Nonnull CallContext<R, T> callContext, @Nonnull IHook<R, T, S, P> hook) {
        List<IHookDetectionObserver<R, T, S, P>> subscribers = listeners.get(hook.hookValue());
        if (subscribers == null) {
            return;
        }
        /*
         * Exception in thread "main" java.util.ConcurrentModificationException
         *
         * ConcurrentModificationException can be resolved by traversing the elements of the ArrayList using a
         * traditional for loop instead of the enhanced for loop. Since the traditional for loop does not use an
         * Iterator to traverse the elements of a Collection, it does not cause a ConcurrentModificationException.
         */
        for (int i = 0; i < subscribers.size(); i++) {
            subscribers.get(i).onHookInvocation(callContext, hook);
        }
    }
}
