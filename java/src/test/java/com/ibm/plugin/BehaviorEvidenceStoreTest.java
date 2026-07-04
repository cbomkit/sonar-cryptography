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
package com.ibm.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.model.context.AuthContext;
import com.ibm.engine.model.context.CipherContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class BehaviorEvidenceStoreTest {

    @BeforeEach
    void reset() {
        BehaviorEvidenceStore.reset();
    }

    @Test
    void recordsAuthContextKind() {
        final boolean recorded =
                BehaviorEvidenceStore.recordFrom(new AuthContext(AuthContext.Kind.JWT));
        assertThat(recorded).isTrue();
        assertThat(BehaviorEvidenceStore.getSignals()).containsExactly(AuthContext.Kind.JWT);
    }

    @Test
    void ignoresNonAuthContext() {
        final boolean recorded = BehaviorEvidenceStore.recordFrom(new CipherContext());
        assertThat(recorded).isFalse();
        assertThat(BehaviorEvidenceStore.getSignals()).isEmpty();
    }

    @Test
    void ignoresNoneKind() {
        final boolean recorded = BehaviorEvidenceStore.recordFrom(new AuthContext());
        assertThat(recorded).isFalse();
        assertThat(BehaviorEvidenceStore.getSignals()).isEmpty();
    }

    @Test
    void resetClearsSignals() {
        BehaviorEvidenceStore.recordFrom(new AuthContext(AuthContext.Kind.PRINCIPAL));
        BehaviorEvidenceStore.reset();
        assertThat(BehaviorEvidenceStore.getSignals()).isEmpty();
    }
}
