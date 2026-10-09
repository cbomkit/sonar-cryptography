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
 * A call is matched with the function C++ name lookup finds for it: a function of a namespace
 * called with its namespace, or without it from inside the namespace or a namespace inside it, also
 * when the function is defined outside its namespace; and a member function called without an
 * object, or on {@code this}, from another member function of its class. A function of a namespace
 * is not the global function of the same name.
 */
class CxxScopedCallTest {

    @AfterEach
    void resetSharedState() {
        CxxAggregator.reset();
    }

    @Test
    void test() {
        CxxVerifier.verifyFiles(
                List.of("rules/detection/CxxScopedCallTestFile.cc"), new CxxInventoryRule());

        assertThat(CxxAggregator.getDetectedNodes())
                .extracting(INode::asString)
                .containsExactlyInAnyOrder(
                        "SHA-224",
                        "SHA-256",
                        "SHA-384",
                        "SHA-512",
                        "SHA3-224",
                        "SHA3-256",
                        "SHA3-384");
    }
}
