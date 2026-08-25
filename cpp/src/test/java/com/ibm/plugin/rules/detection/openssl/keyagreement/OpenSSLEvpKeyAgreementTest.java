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

/** Covers all rule entries in {@link OpenSSLEvpKeyAgreement}. Dispatches on value string. */
class OpenSSLEvpKeyAgreementTest extends TestBase {

    private int findingCount = 0;
    private final Set<String> observed = new HashSet<>();

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/keyagreement/OpenSSLEvpKeyAgreementTestFile.cc", this);
        // findingCount includes the ffdhe2048_nid local-variable call (resolved via
        // CxxSymbolResolverVisitor); observed stays the same size since it resolves to "DH-2048",
        // already produced by its literal counterpart.
        assertThat(findingCount).isEqualTo(27);
        assertThat(observed).hasSize(15);
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

        // EVP_PKEY_CTX_set_dh_kdf_md/set_ecdh_kdf_md raise no finding on the call itself; their
        // md argument is traced back to its constructing call (see OpenSSLEvpMessageDigest),
        // which surfaces here as its own DigestContext entry.
        if (detectionStore.getDetectionValueContext() instanceof DigestContext) {
            findingCount++;
            assertThat(value.asString()).isEqualTo("SHA-256");
            assertThat(nodes).hasSize(1);
            return;
        }

        assertThat(detectionStore.getDetectionValueContext())
                .isInstanceOf(KeyAgreementContext.class);

        String v = value.asString();
        observed.add(v);
        findingCount++;

        switch (v) {
            // EVP_KEYEXCH_fetch(NULL, "ECDH", NULL): real algorithm name resolved via
            // CxxKeyAgreementContextTranslator's Algorithm branch.
            case "ECDH" -> assertThat(nodes).hasSize(1);
            // EVP_PKEY_CTX_set_dh_nid(ctx, 1126 /* NID_ffdhe2048 */): real NID resolved via
            // OpenSSLNidLookupFactory.
            case "DH-2048" -> assertThat(nodes).hasSize(1);
            // EVP_KEM_fetch(NULL, "RSA", NULL): "RSA" is a real captured value, but
            // CxxKeyAgreementContextTranslator has no RSA-as-KEM case, so it resolves to nothing.
            // OSSL_HPKE_str2suite's real suite string is captured but not modeled either.
            case "RSA", "X25519,HKDF-SHA256,AES-128-GCM" -> assertThat(nodes).isEmpty();
            case "DERIVE",
                    "DH-KDF-TYPE",
                    "DH-PARAMGEN",
                    "DH-RFC5114",
                    "DHX-RFC5114",
                    // EVP_PKEY_CTX_set_ecdh_kdf_type(ctx, 1): CxxKeyAgreementContextTranslator
                    // has no case for this marker, so it resolves to no node.
                    "ECDH-KDF-TYPE",
                    "ENCAPSULATE",
                    "DECAPSULATE",
                    "AUTH-ENCAPSULATE",
                    "AUTH-DECAPSULATE",
                    "HPKE" ->
                    // EVP_PKEY_derive, EVP_KEM_encapsulate, HPKE calls, ...: none of these carry
                    // an algorithm-name parameter to trace.
                    assertThat(nodes).isEmpty();
            default -> throw new AssertionError("Unexpected value: " + v);
        }
    }
}
