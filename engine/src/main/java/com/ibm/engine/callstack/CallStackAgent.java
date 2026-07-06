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
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import javax.annotation.Nonnull;
import org.sonar.api.batch.fs.InputFile;

public class CallStackAgent<R, T, S, P>
        implements INotifyWhenNewCallWasAddedOntoTheCallStack<R, T>,
                INewHookSubscription<R, T, S, P> {
    @Nonnull
    private final ConcurrentMap<Integer, List<CallContext<R, T>>> invokedCallStack =
            new ConcurrentHashMap<>();

    @Nonnull private final List<IObserver<CallContext<R, T>>> listeners = new ArrayList<>();
    @Nonnull private final ILanguageSupport<R, T, S, P> languageSupport;

    public CallStackAgent(@Nonnull ILanguageSupport<R, T, S, P> languageSupport) {
        this.languageSupport = languageSupport;
    }

    public void addCall(@Nonnull T tree, @Nonnull IScanContext<R, T> scanContext) {
        add(new RetainedCall<>(tree, scanContext, null));
    }

    /**
     * Detaches the just-analyzed file's still-retained calls: each {@link RetainedCall} for {@code
     * inputFile} that carries a pre-built {@link RetainedCall#detachedForm()} is replaced by that
     * tree-free form, so the file's AST becomes garbage-collectable while cross-file matching
     * continues from the snapshot. Same-file detections have already fired (with the live context)
     * before this runs, so their SonarQube issues are unaffected.
     */
    public void detachCallsForFile(@Nonnull InputFile inputFile) {
        for (List<CallContext<R, T>> bucket : invokedCallStack.values()) {
            for (int i = 0; i < bucket.size(); i++) {
                if (bucket.get(i) instanceof RetainedCall<R, T> retained
                        && retained.detachedForm() != null
                        && inputFile.equals(retained.publisher().getInputFile())) {
                    bucket.set(i, retained.detachedForm());
                }
            }
        }
    }

    /** Read-only snapshot of the recorded-call population (retained-with-tree vs. detached). */
    @Nonnull
    public CallContextStats callContextStats() {
        return CallContextStats.from(invokedCallStack.values());
    }

    /** Records a call (retained or detached) and notifies live hook subscriptions. */
    public void add(@Nonnull CallContext<R, T> callContext) {
        final Optional<Integer> keyOptional = keyOf(callContext);
        if (keyOptional.isEmpty()) {
            return;
        }
        if (addedToCallContext(keyOptional.get(), callContext)) {
            this.notify(callContext);
        }
    }

    @Nonnull
    private Optional<Integer> keyOf(@Nonnull CallContext<R, T> callContext) {
        if (callContext instanceof DetachedCall<R, T> detached) {
            return Optional.of(detached.methodName().hashCode());
        }
        final T tree = callContext.tree();
        return tree == null ? Optional.empty() : getKeyFormT(tree);
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
        final Iterator<List<CallContext<R, T>>> iterator = bucketsToScan(methodMatcher).iterator();
        while (iterator.hasNext()) {
            final List<CallContext<R, T>> callContexts = iterator.next();
            final Iterator<CallContext<R, T>> callContextIterator = callContexts.iterator();
            while (callContextIterator.hasNext()) {
                final CallContext<R, T> callContext = callContextIterator.next();
                if (matches(methodMatcher, callContext, hook)) {
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

    /**
     * The call-stack buckets a hook's matcher could match. Recorded calls are keyed by their
     * invoked method name's hash, so a single-name matcher only needs that one bucket; {@code
     * ANY}/multi-name matchers fall back to scanning every bucket.
     */
    @Nonnull
    private Collection<List<CallContext<R, T>>> bucketsToScan(
            @Nonnull MethodMatcher<T> methodMatcher) {
        final List<String> methodNames = methodMatcher.getMethodNamesSerializable();
        if (methodNames.size() == 1 && !MethodMatcher.ANY.equals(methodNames.get(0))) {
            final List<CallContext<R, T>> bucket =
                    invokedCallStack.get(methodNames.get(0).hashCode());
            return bucket == null ? List.of() : List.of(bucket);
        }
        return invokedCallStack.values();
    }

    private boolean matches(
            @Nonnull MethodMatcher<T> methodMatcher,
            @Nonnull CallContext<R, T> callContext,
            @Nonnull IHook<R, T, S, P> hook) {
        if (callContext instanceof DetachedCall<R, T> detached) {
            return methodMatcher.matchKeys(
                    detached.invokedObjectType(), detached.methodName(), detached.parameterTypes());
        }
        final T tree = callContext.tree();
        return tree != null
                && methodMatcher.match(tree, languageSupport.translation(), hook.matchContext());
    }

    private boolean addedToCallContext(int key, @Nonnull CallContext<R, T> callContext) {
        final T tree = callContext.tree();
        final boolean[] added = {true};
        invokedCallStack.compute(
                key,
                (k, v) -> {
                    final List<CallContext<R, T>> callContexts =
                            (v == null) ? new ArrayList<>() : v;
                    if (tree != null) {
                        for (CallContext<R, T> existing : callContexts) {
                            if (tree.equals(existing.tree())) {
                                added[0] = false;
                                return callContexts;
                            }
                        }
                    }
                    callContexts.add(callContext);
                    return callContexts;
                });
        return added[0];
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
