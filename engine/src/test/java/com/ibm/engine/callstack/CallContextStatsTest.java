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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;
import static org.mockito.Mockito.mock;

import com.ibm.engine.language.IScanContext;
import java.util.List;
import org.junit.jupiter.api.Test;

class CallContextStatsTest {

    @Test
    @SuppressWarnings("unchecked")
    void countsRetainedAndDetachedAcrossBuckets() {
        IScanContext<Object, String> ctx = mock(IScanContext.class);
        RetainedCall<Object, String> retained1 = new RetainedCall<>("t1", ctx, null);
        RetainedCall<Object, String> retained2 = new RetainedCall<>("t2", ctx, null);
        DetachedCall<Object, String> detached = mock(DetachedCall.class);

        List<List<CallContext<Object, String>>> buckets =
                List.of(List.of(retained1, detached), List.of(retained2));

        CallContextStats stats = CallContextStats.from(buckets);

        assertThat(stats.retainedWithTree()).isEqualTo(2);
        assertThat(stats.detached()).isEqualTo(1);
        assertThat(stats.total()).isEqualTo(3);
        assertThat(stats.buckets()).isEqualTo(2);
        assertThat(stats.detachedRatio()).isCloseTo(1.0d / 3.0d, within(1e-9));
    }

    @Test
    void emptyHasZeroCountsAndFullRatio() {
        assertThat(CallContextStats.EMPTY.total()).isZero();
        assertThat(CallContextStats.EMPTY.buckets()).isZero();
        assertThat(CallContextStats.EMPTY.detachedRatio()).isEqualTo(1.0d);
    }
}
