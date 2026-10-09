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
package com.ibm.rules;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.rules.issue.Issue;
import java.util.List;
import org.junit.jupiter.api.Test;

final class InventoryRuleTest {

    // reproduces the exact detection shape of the openssl-cxx-demo scan: one top-level node
    // per detected algorithm/protocol, no children, as InventoryRule.report receives it.

    @Test
    void reportsTopLevelAlgorithm() {
        final AES aes = new AES(256, detectionLocation());

        final InventoryRule<IMockTree> rule = new InventoryRule<>();
        final List<Issue<IMockTree>> issues = rule.report(new MockTree(), List.of(aes));

        assertThat(issues).hasSize(1);
    }

    @Test
    void reportsTopLevelMessageDigestAlgorithm() {
        final SHA2 sha256 = new SHA2(256, detectionLocation());

        final InventoryRule<IMockTree> rule = new InventoryRule<>();
        final List<Issue<IMockTree>> issues = rule.report(new MockTree(), List.of(sha256));

        assertThat(issues).hasSize(1);
    }

    @Test
    void reportsTopLevelPublicKeyAlgorithm() {
        final RSA rsa = new RSA(2048, detectionLocation());

        final InventoryRule<IMockTree> rule = new InventoryRule<>();
        final List<Issue<IMockTree>> issues = rule.report(new MockTree(), List.of(rsa));

        assertThat(issues).hasSize(1);
    }

    @Test
    void reportsTopLevelProtocol() {
        final TLS tls = new TLS(detectionLocation());

        final InventoryRule<IMockTree> rule = new InventoryRule<>();
        final List<Issue<IMockTree>> issues = rule.report(new MockTree(), List.of(tls));

        assertThat(issues).hasSize(1);
    }

    @Test
    void reportsAllFourTogetherLikeOpensslDemoScan() {
        final List<com.ibm.mapper.model.INode> nodes =
                List.of(
                        new AES(256, detectionLocation()),
                        new SHA2(256, detectionLocation()),
                        new RSA(2048, detectionLocation()),
                        new TLS(detectionLocation()));

        final InventoryRule<IMockTree> rule = new InventoryRule<>();
        final List<Issue<IMockTree>> issues = rule.report(new MockTree(), nodes);

        assertThat(issues).hasSize(4);
    }

    private static com.ibm.mapper.utils.DetectionLocation detectionLocation() {
        return new com.ibm.mapper.utils.DetectionLocation(
                "test.cc", 1, 1, java.util.Collections.emptyList(), () -> "Test");
    }
}
