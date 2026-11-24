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
package com.ibm.plugin;

import javax.annotation.Nonnull;

/**
 * End-of-scan snapshot of the three heap populations whose relative size decides the H1
 * attribution: retained CBOM nodes, detached call-stack records, and the call-stack bucket count.
 * Counts only — byte attribution is the manual {@code jmap} runbook in {@code
 * docs/PERFORMANCE_TESTING.md}.
 *
 * @param detectedNodes retained CBOM {@code INode}s (Java aggregator)
 * @param detachedCalls tree-free {@code DetachedCall}s in the call stack
 * @param totalCalls total recorded calls (detached + retained-with-tree)
 * @param callStackBuckets number of hash buckets in the call stack
 */
public record HeapAttributionSummary(
        int detectedNodes, int detachedCalls, int totalCalls, int callStackBuckets) {

    @Nonnull
    public String format() {
        return "[heap-attribution] detectedNodes="
                + detectedNodes
                + " detachedCalls="
                + detachedCalls
                + " totalCalls="
                + totalCalls
                + " callStackBuckets="
                + callStackBuckets;
    }
}
