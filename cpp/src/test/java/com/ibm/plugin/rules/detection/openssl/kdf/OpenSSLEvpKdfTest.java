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
package com.ibm.plugin.rules.detection.openssl.kdf;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.algorithms.PBKDF2;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
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
 * Covers all rule entries in {@link OpenSSLEvpKdf}.
 *
 * <p>{@code EVP_KDF_fetch(lib, "PBKDF2", props)}-style calls raise one finding per KDF family (the
 * real fetched name, e.g. {@code "PBKDF2"}) rather than guessing a digest that isn't visible at the
 * fetch call site; {@link
 * com.ibm.plugin.translation.translator.contexts.CxxKeyDerivationFunctionContextTranslator} has no
 * case for a bare family name, so those resolve to no node. The real digest, when the code sets one
 * via {@code EVP_KDF_CTX_set_params(kctx, params)}, is a separate, independently traced finding:
 * {@code params} is resolved back to its {@code OSSL_PARAM params[] = {...}} declaration (see
 * {@link com.ibm.engine.language.cxx.CxxSemantic#resolveValues}), and {@link
 * OpenSSLParamsScannerFactory} scans that array for the {@code "digest"}-keyed entry.
 */
class OpenSSLEvpKdfTest extends TestBase {

    private int findingCount = 0;
    private final Set<String> observed = new HashSet<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/kdf/OpenSSLEvpKdfTestFile.cc", this);
        assertThat(findingCount).isEqualTo(42);
        assertThat(observed).hasSize(28);
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

        // EVP_PKEY_CTX_set_hkdf_md/set_tls1_prf_md raise no finding on the call itself; their md
        // argument is traced back to its constructing call (see OpenSSLEvpMessageDigest). Same for
        // EVP_KDF_CTX_set_params's "digest" OSSL_PARAM entry (see OpenSSLParamsScannerFactory).
        // Both surface here as their own DigestContext entry.
        if (detectionStore.getDetectionValueContext() instanceof DigestContext) {
            observed.add(value.asString());
            findingCount++;
            assertThat(value.asString()).isEqualTo("SHA-256");
            assertThat(nodes).hasSize(1);
            return;
        }

        assertThat(detectionStore.getDetectionValueContext())
                .isInstanceOf(KeyDerivationFunctionContext.class);

        String v = value.asString();
        observed.add(v);
        findingCount++;

        if (v.equals("PBKDF2-HMAC")) {
            assertPbkdf2WithSha256(nodes);
        } else if (v.equals("PBKDF2-HMAC-SHA1")) {
            assertPbkdf2WithSha1(nodes);
        } else if (v.equals("PBKDF2")
                || v.equals("HKDF")
                || v.equals("TLS1-PRF")
                || v.equals("TLS13-KDF")
                || v.equals("X963KDF")
                || v.equals("KBKDF")
                || v.equals("SSHKDF")) {
            // Bare KDF family name with no digest visible at the fetch call site -
            // CxxKeyDerivationFunctionContextTranslator has no case for it, so it resolves to
            // nothing.
            assertThat(nodes).isEmpty();
        } else if (v.equals("SCRYPT")) {
            assertSimpleAlgo(nodes, com.ibm.mapper.model.algorithms.Scrypt.class, "scrypt");
        } else if (v.equals("X942KDF-ASN1") || v.equals("X942KDF-CONCAT")) {
            assertSimpleAlgo(
                    nodes, com.ibm.mapper.model.algorithms.ANSIX942.class, "ANSI-KDF-X9.42");
        } else if (v.equals("SSKDF")) {
            assertSimpleAlgo(
                    nodes,
                    com.ibm.mapper.model.algorithms.ConcatenationKDF.class,
                    "ConcatenationKDF");
        } else if (v.equals("KRB5KDF")) {
            assertGenericKdf(nodes, "KRB5KDF", KeyDerivationFunction.class);
        } else if (v.equals("ARGON2D")) {
            assertGenericKdf(nodes, "Argon2d", PasswordBasedKeyDerivationFunction.class);
        } else if (v.equals("ARGON2I")) {
            assertGenericKdf(nodes, "Argon2i", PasswordBasedKeyDerivationFunction.class);
        } else if (v.equals("ARGON2ID")) {
            assertGenericKdf(nodes, "Argon2id", PasswordBasedKeyDerivationFunction.class);
        } else if (v.equals("PKCS12KDF")) {
            assertGenericKdf(nodes, "PKCS12KDF", PasswordBasedKeyDerivationFunction.class);
        } else if (v.equals("PVKKDF")) {
            assertGenericKdf(nodes, "PVKKDF", PasswordBasedKeyDerivationFunction.class);
        } else if (v.equals("HMAC-DRBG-KDF")) {
            assertGenericKdf(nodes, "HMAC-DRBG-KDF", KeyDerivationFunction.class);
        } else if (v.equals("HKDF-MODE")
                || v.equals("KDF-CTX")
                || v.equals("PBE-KEYIVGEN")
                || v.equals("PKCS12")
                || v.equals("PKCS12-MAC")
                || v.equals("PKCS12-PBE")
                || v.equals("PKCS12-KDF")) {
            // None of these API calls carry an algorithm-name parameter to trace.
            assertThat(nodes).isEmpty();
        } else {
            throw new AssertionError("Unexpected value: " + v);
        }
    }

    /* helpers */

    private static INode head(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        return nodes.get(0);
    }

    private static void assertSimpleAlgo(
            List<INode> nodes, Class<? extends INode> klass, String asString) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(klass);
        assertThat(n.asString()).isEqualTo(asString);
    }

    private static void assertGenericKdf(List<INode> nodes, String asString, Class<?> kindClass) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(Algorithm.class);
        assertThat(n.getKind()).isEqualTo(kindClass);
        assertThat(n.asString()).isEqualTo(asString);
    }

    private static void assertPbkdf2WithSha1(List<INode> nodes) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(PBKDF2.class);
        assertThat(n.asString()).isEqualTo("PBKDF2-SHA-1");
        INode digest = n.getChildren().get(com.ibm.mapper.model.MessageDigest.class);
        assertThat(digest).isNotNull().isInstanceOf(SHA.class);
        assertThat(digest.asString()).isEqualTo("SHA-1");
    }

    private static void assertPbkdf2WithSha256(List<INode> nodes) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(PBKDF2.class);
        assertThat(n.asString()).isEqualTo("PBKDF2-SHA-256");
        INode digest = n.getChildren().get(com.ibm.mapper.model.MessageDigest.class);
        assertThat(digest).isNotNull().isInstanceOf(SHA2.class);
        assertThat(digest.asString()).isEqualTo("SHA-256");
    }
}
