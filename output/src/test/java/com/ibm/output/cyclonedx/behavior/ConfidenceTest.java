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
package com.ibm.output.cyclonedx.behavior;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.output.cyclondx.behavior.Confidence;
import com.ibm.output.cyclondx.behavior.CryptoBehavior;
import org.junit.jupiter.api.Test;

class ConfidenceTest {

    @Test
    void tokensAreLowercaseWords() {
        assertThat(Confidence.HIGH.token()).isEqualTo("high");
        assertThat(Confidence.MEDIUM.token()).isEqualTo("medium");
    }

    @Test
    void newAppLevelBehaviorsExposeFullId() {
        assertThat(CryptoBehavior.VALIDATES_TOKEN.fullId())
                .isEqualTo("security:cryptography:validatesToken");
        assertThat(CryptoBehavior.USES_IDENTITY.fullId())
                .isEqualTo("security:cryptography:usesIdentity");
    }
}
