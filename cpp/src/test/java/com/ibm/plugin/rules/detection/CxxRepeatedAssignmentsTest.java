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
package com.ibm.plugin.rules.detection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.plugin.CxxAggregator;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.rules.CxxInventoryRule;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * A variable assigned several times from another variable that is itself assigned several times
 * resolves each variable once, not once per path through the assignments.
 */
class CxxRepeatedAssignmentsTest {

    @AfterEach
    void resetSharedState() {
        CxxAggregator.reset();
    }

    @Test
    void aChainOfRepeatedAssignmentsResolvesInLinearTime() {
        assertTimeoutPreemptively(
                Duration.ofSeconds(10),
                () ->
                        CxxVerifier.verifyFiles(
                                List.of(
                                        "rules/detection/robustness/CxxRepeatedAssignmentsTestFile.cc"),
                                new CxxInventoryRule()));

        assertThat(CxxAggregator.getDetectedNodes()).hasSize(1);
        final INode key = CxxAggregator.getDetectedNodes().get(0);
        assertThat(key.asString()).isEqualTo("RSA");
        assertThat(key.hasChildOfType(KeyLength.class)).map(INode::asString).contains("2048");
    }
}
