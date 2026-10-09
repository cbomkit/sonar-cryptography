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
package com.ibm.plugin.rules.detection.openssl.legacy;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Signature;
import com.ibm.plugin.CxxAggregator;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.rules.CxxInventoryRule;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * An operation of the legacy API is reported with the key it is made with when the key is set up in
 * the analyzed code: a cipher with its key schedule, and a signature or key agreement with the key
 * generated for it, as an operation of the EVP API is reported with its key.
 */
class OpenSSLLegacyKeyUsageTest {

    @AfterEach
    void resetSharedState() {
        CxxAggregator.reset();
    }

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/legacy/OpenSSLLegacyKeyUsageTestFile.cc",
                new CxxInventoryRule());

        assertThat(CxxAggregator.getDetectedNodes())
                .extracting(OpenSSLLegacyKeyUsageTest::operationsOf)
                .containsExactly(
                        List.of("Mode:ECB", "KeyLength:56"),
                        List.of("Mode:ECB", "KeyLength:128"),
                        List.of("Signature:ECDSA-secp256r1"),
                        List.of("KeyAgreement:ECDH[EllipticCurve:secp384r1]"),
                        List.of("Signature:RSA-PKCS1-1.5-SHA-256"),
                        List.of("Signature:DSA-2048"),
                        List.of("KeyAgreement:FFDH[KeyLength:2048]"));
    }

    /** A key agreement with the curve or the key length of its key, any other node by name. */
    @Nonnull
    private static String describe(@Nonnull INode node) {
        if (!node.is(KeyAgreement.class)) {
            return node.asString();
        }
        return node.asString()
                + node.getChildren().values().stream()
                        .filter(child -> child.is(EllipticCurve.class) || child.is(KeyLength.class))
                        .map(child -> child.getKind().getSimpleName() + ":" + child.asString())
                        .toList();
    }

    /**
     * The operations a key is reported with (its signatures and key agreements), or the mode and
     * key length of a cipher.
     */
    @Nonnull
    private static List<String> operationsOf(@Nonnull INode node) {
        return node.getChildren().values().stream()
                .filter(
                        child ->
                                child.is(Signature.class)
                                        || child.is(KeyAgreement.class)
                                        || child.is(Mode.class)
                                        || (child.is(KeyLength.class)
                                                && node.is(BlockCipher.class)))
                .map(child -> child.getKind().getSimpleName() + ":" + describe(child))
                .sorted(
                        java.util.Comparator.comparing(
                                (String operation) -> !operation.startsWith("Mode")))
                .toList();
    }
}
