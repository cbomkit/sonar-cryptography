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
package com.ibm.mapper.model;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Collections;
import org.junit.jupiter.api.Test;

class ContextualEvidenceTest {

    private final IBundle bundle = () -> "Test";
    private final DetectionLocation location =
            new DetectionLocation("Test.java", 1, 1, Collections.emptyList(), bundle);

    @Test
    void carriesIdentifierAndKind() {
        final ContextualEvidence evidence = new ContextualEvidence("JWT", location);
        assertThat(evidence.identifier()).isEqualTo("JWT");
        assertThat(evidence.asString()).isEqualTo("JWT");
        assertThat(evidence.getKind()).isEqualTo(ContextualEvidence.class);
        assertThat(evidence.is(ContextualEvidence.class)).isTrue();
    }

    @Test
    void deepCopyEqualsOriginal() {
        final ContextualEvidence evidence = new ContextualEvidence("PRINCIPAL", location);
        assertThat(evidence.deepCopy()).isEqualTo(evidence);
    }
}
