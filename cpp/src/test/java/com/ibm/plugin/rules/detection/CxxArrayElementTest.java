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

import com.ibm.mapper.model.INode;
import com.ibm.plugin.CxxAggregator;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.rules.CxxInventoryRule;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * An element of an array resolves to the elements of the array's initializer and the values
 * assigned to its elements: the element at a constant index, counting designated elements at their
 * index, or every element for an index that is not constant, also of an array of arrays. An index
 * out of the initializer's range gives no value.
 */
class CxxArrayElementTest {

    @AfterEach
    void resetSharedState() {
        CxxAggregator.reset();
    }

    @Test
    void test() {
        CxxVerifier.verifyFiles(
                List.of("rules/detection/CxxArrayElementTestFile.c"), new CxxInventoryRule());

        assertThat(CxxAggregator.getDetectedNodes())
                .extracting(INode::asString)
                .containsExactly(
                        "SHA-1",
                        "SHA-256",
                        "MD5",
                        "SHA-512",
                        "SHA-512/224",
                        "SHA-512/256",
                        "SM3",
                        "BLAKE2b-512",
                        "BLAKE2s-256",
                        "SHA3-224",
                        "SHA3-256");
    }
}
