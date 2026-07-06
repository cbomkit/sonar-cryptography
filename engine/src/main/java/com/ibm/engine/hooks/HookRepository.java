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

import com.ibm.common.IDomainEvents;
import com.ibm.common.IObservers;
import com.ibm.engine.callstack.CallContext;
import com.ibm.engine.callstack.IGetNotifiedWhenNewCallWasAddedToCallStack;
import com.ibm.engine.detection.Handler;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.annotation.Nonnull;

public class HookRepository<R, T, S, P>
        implements IGetNotifiedWhenNewCallWasAddedToCallStack<R, T>,
                IDomainEvents<HookRepository.Event, IHook<R, T, S, P>> {
    @Nonnull private final Set<IHook<R, T, S, P>> hookSet = ConcurrentHashMap.newKeySet();

    @Nonnull
    private final Map<Event, List<IObservers<Event, IHook<R, T, S, P>>>> listeners =
            new EnumMap<>(Event.class);

    @Nonnull private final Handler<R, T, S, P> handler;

    public enum Event {
        HOOK_ADDED,
        HOOK_REMOVED
    }

    public HookRepository(@Nonnull Handler<R, T, S, P> handler) {
        this.handler = handler;

        listeners.putIfAbsent(Event.HOOK_ADDED, new ArrayList<>());
        listeners.putIfAbsent(Event.HOOK_REMOVED, new ArrayList<>());
        // listen to callstack events
        this.handler.subscribeToCallStackAgent(this);
    }

    public boolean add(@Nonnull IHook<R, T, S, P> hook) {
        boolean res = hookSet.add(hook);
        if (res) {
            this.notify(Event.HOOK_ADDED, hook);
        }
        return res;
    }

    public boolean delete(@Nonnull IHook<R, T, S, P> hook) {
        boolean res = hookSet.remove(hook);
        if (res) {
            this.notify(Event.HOOK_REMOVED, hook);
        }
        return res;
    }

    @Override
    public void subscribe(
            @Nonnull Event event, @Nonnull IObservers<Event, IHook<R, T, S, P>> listener) {
        List<IObservers<Event, IHook<R, T, S, P>>> subscribers = listeners.get(event);
        subscribers.add(listener);
    }

    @Override
    public void unsubscribe(
            @Nonnull Event event, @Nonnull IObservers<Event, IHook<R, T, S, P>> listener) {
        List<IObservers<Event, IHook<R, T, S, P>>> subscribers = listeners.get(event);
        subscribers.remove(listener);
    }

    @Override
    public void notify(@Nonnull Event event, @Nonnull IHook<R, T, S, P> object) {
        List<IObservers<Event, IHook<R, T, S, P>>> subscribers = listeners.get(event);
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
        for (IObservers<Event, IHook<R, T, S, P>> observer : subscribers) {
            observer.update(event, object);
        }
    }

    /**
     * Check if hook is registered to trigger hook detection event for {@link CallContext}.
     *
     * @param callContext The context in which to update the hooks. This should include information
     *     about the current state of the system, such as the current request and response objects.
     */
    @Override
    public void update(@Nonnull final CallContext<R, T> callContext) {
        hookSet.stream()
                .filter(hook -> hook.isInvocationOn(callContext, handler.getLanguageSupport()))
                .forEach(hook -> handler.notifyAllHookDetectionObservers(callContext, hook));
    }
}
