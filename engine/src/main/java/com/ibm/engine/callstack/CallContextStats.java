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
package com.ibm.engine.callstack;

import java.util.Collection;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Immutable snapshot of the {@link CallStackAgent}'s recorded-call population, used by the
 * performance/heap harness to assert that calls were detached (ASTs released) at {@code leaveFile}.
 *
 * @param retainedWithTree number of {@link RetainedCall}s still pinning a live AST tree
 * @param detached number of tree-free {@link DetachedCall}s
 * @param total {@code retainedWithTree + detached}
 * @param buckets number of hash buckets in the call stack
 */
public record CallContextStats(int retainedWithTree, int detached, int total, int buckets) {

    /** A zero-valued snapshot (used as the language-agnostic default). */
    public static final CallContextStats EMPTY = new CallContextStats(0, 0, 0, 0);

    /** Fraction of recorded calls that are detached; {@code 1.0} when nothing was recorded. */
    public double detachedRatio() {
        return total == 0 ? 1.0d : (double) detached / (double) total;
    }

    /** Counts retained-with-tree vs. detached calls across all call-stack buckets. */
    @Nonnull
    public static <R, T> CallContextStats from(
            @Nonnull Collection<List<CallContext<R, T>>> buckets) {
        int retainedWithTree = 0;
        int detached = 0;
        for (List<CallContext<R, T>> bucket : buckets) {
            for (CallContext<R, T> call : bucket) {
                if (call instanceof DetachedCall<R, T>) {
                    detached++;
                } else if (call instanceof RetainedCall<R, T> retained && retained.tree() != null) {
                    retainedWithTree++;
                }
            }
        }
        return new CallContextStats(
                retainedWithTree, detached, retainedWithTree + detached, buckets.size());
    }
}
