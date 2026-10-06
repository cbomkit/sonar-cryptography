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
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Signature;
import com.ibm.plugin.CxxAggregator;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.rules.CxxInventoryRule;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * A value found through a hook for a depending rule, the digest name given to the function that
 * signs, is reported with the operation it is used by and not again on its own, although the rule
 * it was found for is also a rule of its own.
 */
class CxxHookValueTest {

    @AfterEach
    void resetSharedState() {
        CxxAggregator.reset();
    }

    @Test
    void test() {
        CxxVerifier.verifyFiles(
                List.of("rules/detection/CxxHookValueTestFile.cc"), new CxxInventoryRule());

        assertThat(CxxAggregator.getDetectedNodes())
                .singleElement()
                .satisfies(
                        signature -> {
                            assertThat(signature.is(Signature.class)).isTrue();
                            assertThat(signature.hasChildOfType(MessageDigest.class))
                                    .map(INode::asString)
                                    .contains("SHA-256");
                        });
    }
}
