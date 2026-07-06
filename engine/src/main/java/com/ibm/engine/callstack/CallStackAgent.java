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

import com.ibm.common.IObserver;
import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.hooks.IHook;
import com.ibm.engine.hooks.IHookDetectionObserver;
import com.ibm.engine.language.ILanguageSupport;
import com.ibm.engine.language.IScanContext;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import javax.annotation.Nonnull;

public class CallStackAgent<R, T, S, P>
        implements INotifyWhenNewCallWasAddedOntoTheCallStack<R, T>,
                INewHookSubscription<R, T, S, P> {
    @Nonnull
    private final ConcurrentMap<Integer, List<CallContext<R, T>>> invokedCallStack =
            new ConcurrentHashMap<>();

    @Nonnull private final Set<T> visitedTreeObjects = ConcurrentHashMap.newKeySet();
    @Nonnull private final List<IObserver<CallContext<R, T>>> listeners = new ArrayList<>();
    @Nonnull private final ILanguageSupport<R, T, S, P> languageSupport;

    public CallStackAgent(@Nonnull ILanguageSupport<R, T, S, P> languageSupport) {
        this.languageSupport = languageSupport;
    }

    public void addCall(@Nonnull T tree, @Nonnull IScanContext<R, T> scanContext) {
        Optional<Integer> keyOptional = getKeyFormT(tree);
        if (keyOptional.isEmpty()) {
            return;
        }

        int key = keyOptional.get();
        final CallContext<R, T> callContext = new RetainedCall<>(tree, scanContext);
        if (addedToCallContext(key, callContext)) {
            this.notify(callContext);
        }
    }

    @Override
    public void subscribe(@Nonnull IObserver<CallContext<R, T>> listener) {
        listeners.add(listener);
    }

    @Override
    public void unsubscribe(@Nonnull IObserver<CallContext<R, T>> listener) {
        listeners.remove(listener);
    }

    @Override
    public void notify(@Nonnull CallContext<R, T> callContext) {
        /*
         * Exception in thread "main" java.util.ConcurrentModificationException
         *
         * ConcurrentModificationException can be resolved by traversing the elements of the ArrayList using a
         * traditional for loop instead of the enhanced for loop. Since the traditional for loop does not use an
         * Iterator to traverse the elements of a Collection, it does not cause a ConcurrentModificationException.
         */
        for (int i = 0; i < listeners.size(); i++) {
            listeners.get(i).update(callContext);
        }
    }

    @Override
    public void onNewHookSubscription(
            @Nonnull IHook<R, T, S, P> hook,
            @Nonnull IHookDetectionObserver<R, T, S, P> hookDetectionObserver) {
        final MethodMatcher<T> methodMatcher =
                languageSupport.createMethodMatcherBasedOn(hook.hookValue());
        if (methodMatcher == null) {
            return;
        }

        final List<CallContext<R, T>> stackCalls = new ArrayList<>();
        final Iterator<List<CallContext<R, T>>> iterator = invokedCallStack.values().iterator();
        while (iterator.hasNext()) {
            final List<CallContext<R, T>> callContexts = iterator.next();
            final Iterator<CallContext<R, T>> callContextIterator = callContexts.iterator();
            while (callContextIterator.hasNext()) {
                final CallContext<R, T> callContext = callContextIterator.next();
                if (methodMatcher.match(
                        callContext.tree(), languageSupport.translation(), hook.matchContext())) {
                    stackCalls.add(callContext);
                }
            }
        }

        final Iterator<CallContext<R, T>> callContextIterator = stackCalls.iterator();
        while (callContextIterator.hasNext()) {
            final CallContext<R, T> callContext = callContextIterator.next();
            for (int i = 0; i < listeners.size(); i++) {
                listeners.get(i).update(callContext);
            }
        }
    }

    private boolean addedToCallContext(int key, @Nonnull CallContext<R, T> callContext) {
        if (visitedTreeObjects.contains(callContext.tree())) {
            return false;
        }
        visitedTreeObjects.add(callContext.tree());
        invokedCallStack.compute(
                key,
                (k, v) -> {
                    if (v == null) {
                        final ArrayList<CallContext<R, T>> callContexts = new ArrayList<>();
                        callContexts.add(callContext);
                        return callContexts;
                    } else {
                        v.add(callContext);
                        return v;
                    }
                });
        return true;
    }

    @Nonnull
    private Optional<Integer> getKeyFormT(@Nonnull T tree) {
        final String identifierString =
                languageSupport
                        .translation()
                        .getMethodName(MatchContext.createForHookContext(), tree)
                        .orElse(
                                languageSupport
                                        .translation()
                                        .getEnumClassName(MatchContext.createForHookContext(), tree)
                                        .orElse(null));

        if (identifierString == null) {
            return Optional.empty();
        }
        int key = identifierString.hashCode();
        return Optional.of(key);
    }
}
