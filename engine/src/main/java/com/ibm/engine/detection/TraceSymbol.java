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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * TraceSymbol should extend the Symbol class from ' org.sonar.plugins.java.api.semantic.Symbol'. To
 * be able to resolve related function calls it is not only necessary to check if they are connected
 * through the same symbol, but also to capture the relation state.
 */
public final class TraceSymbol<S> {

    /**
     * DIFFERENT: the variable (symbol) and the resolved function are not connected. The call
     * belongs to a different call stack example: test(a), b = new Test() : a should be resolved and
     * b was detected (type matching), but they do not belong to each other, since a != b NO_SYMBOL:
     * the expected call is not assigned to a variable (symbol) example: test(new Test()) SYMBOL:
     * there is a variable (symbol) and they match example: test(a), a = new Test() SYMBOL_IGNORED:
     * For the first element in a call stack, we have to ignore the assigned variable, since we can
     * not trace further up only down example: Test c = test(a), a = new Test() : we ignore the
     * assigment to c
     */
    public enum State {
        DIFFERENT,
        NO_SYMBOL,
        SYMBOL,
        ASSIGNED_SYMBOL,
        SYMBOL_IGNORED
    }

    private final S symbol;
    private final State state;

    private TraceSymbol(S symbol, State state) {
        this.symbol = symbol;
        this.state = state;
    }

    public S getSymbol() {
        return symbol;
    }

    @Nonnull
    public static <S> TraceSymbol<S> createFrom(@Nullable S symbol) {
        return new TraceSymbol<>(symbol, State.SYMBOL);
    }

    @Nonnull
    public static <S> TraceSymbol<S> createAssignedFrom(@Nullable S symbol) {
        return new TraceSymbol<>(symbol, State.ASSIGNED_SYMBOL);
    }

    @Nonnull
    public static <S> TraceSymbol<S> createWithStateDifferent() {
        return new TraceSymbol<>(null, State.DIFFERENT);
    }

    @Nonnull
    public static <S> TraceSymbol<S> createWithStateNoSymbol() {
        return new TraceSymbol<>(null, State.NO_SYMBOL);
    }

    @Nonnull
    public static <S> TraceSymbol<S> createStart() {
        return new TraceSymbol<>(null, State.SYMBOL_IGNORED);
    }

    public boolean is(State state) {
        return this.state.equals(state);
    }

    public boolean isOneOf(State... states) {
        for (State s : states) {
            if (this.state.equals(s)) {
                return true;
            }
        }
        return false;
    }
}
