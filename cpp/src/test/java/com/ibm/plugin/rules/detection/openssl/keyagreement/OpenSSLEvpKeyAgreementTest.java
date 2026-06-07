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
package com.ibm.plugin.rules.detection.openssl.keyagreement;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.TestBase;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * Covers all 24 rule entries in {@link OpenSSLEvpKeyAgreement}.
 *
 * <p>24 findings, 16 unique detection values. Dispatches on value string.
 */
class OpenSSLEvpKeyAgreementTest extends TestBase {

    private int findingCount = 0;
    private final Set<String> observed = new HashSet<>();

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/keyagreement/OpenSSLEvpKeyAgreementTestFile.cc", this);
        assertThat(findingCount).isEqualTo(24);
        assertThat(observed).hasSize(16);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext())
                .isInstanceOf(KeyAgreementContext.class);
        IValue<AstNode> value = detectionStore.getDetectionValues().get(0);

        String v = value.asString();
        observed.add(v);
        findingCount++;

        switch (v) {
            case "DERIVE",
                    "KEYEXCH-FETCH",
                    "KEM-FETCH",
                    "DH-KDF-TYPE",
                    "DH-KDF-MD",
                    "DH-PARAMGEN",
                    "DH-NID",
                    "DH-RFC5114",
                    "DHX-RFC5114",
                    "ECDH-KDF-TYPE",
                    "ECDH-KDF-MD",
                    "ENCAPSULATE",
                    "DECAPSULATE",
                    "AUTH-ENCAPSULATE",
                    "AUTH-DECAPSULATE",
                    "HPKE" ->
                    assertThat(nodes).isNotNull();
            default -> throw new AssertionError("Unexpected value: " + v);
        }
    }
}
