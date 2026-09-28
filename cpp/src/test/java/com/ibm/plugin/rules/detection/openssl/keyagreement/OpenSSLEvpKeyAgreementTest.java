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
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
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
 * The key exchange, KEM and HPKE suite selections of {@link OpenSSLEvpKeyAgreement} are reported,
 * while the derivation and encapsulation calls, whose key type is not known at the call, and a KDF
 * type of "none" are not. The KDFs and HPKE suite forms are covered by {@link
 * OpenSSLKeyAgreementKdfTest}.
 */
class OpenSSLEvpKeyAgreementTest extends TestBase {

    private int findingCount = 0;
    private final Set<String> observed = new HashSet<>();

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/keyagreement/OpenSSLEvpKeyAgreementTestFile.cc", this);
        assertThat(findingCount).isEqualTo(7);
        assertThat(observed).hasSize(4);
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
        IValue<AstNode> value = detectionStore.getDetectionValues().get(0);

        // the digests assigned to variables are reported on their own
        if (detectionStore.getDetectionValueContext() instanceof DigestContext) {
            findingCount++;
            assertThat(value.asString()).isEqualTo("SHA-256");
            assertThat(nodes).hasSize(1);
            return;
        }

        String v = value.asString();
        observed.add(v);
        findingCount++;

        // EVP_PKEY_CTX_set_dh_kdf_type / set_ecdh_kdf_type(ctx, 1): no KDF is applied
        if (detectionStore.getDetectionValueContext() instanceof KeyDerivationFunctionContext) {
            assertThat(v).isEqualTo("NONE");
            assertThat(nodes).isEmpty();
            return;
        }

        assertThat(detectionStore.getDetectionValueContext())
                .isInstanceOf(KeyAgreementContext.class);

        switch (v) {
            case "ECDH" -> {
                assertThat(nodes).hasSize(1);
                assertThat(nodes.get(0).getKind()).isEqualTo(KeyAgreement.class);
            }
            case "RSA" -> {
                assertThat(nodes).hasSize(1);
                assertThat(nodes.get(0).getKind()).isEqualTo(KeyEncapsulationMechanism.class);
            }
            case "X25519,HKDF-SHA256,AES-128-GCM" -> {
                assertThat(nodes).hasSize(1);
                assertThat(nodes.get(0).asString()).isEqualTo("HPKE");
            }
            default -> throw new AssertionError("Unexpected value: " + v);
        }
    }
}
