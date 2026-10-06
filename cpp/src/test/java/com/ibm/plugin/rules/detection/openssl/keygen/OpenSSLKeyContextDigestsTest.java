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
package com.ibm.plugin.rules.detection.openssl.keygen;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MaskGenerationFunction;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.Signature;
import com.ibm.plugin.CxxAggregator;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.rules.CxxInventoryRule;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The digests set on the context of an operation with a key belong to that operation: the digest of
 * a signature ({@code EVP_PKEY_CTX_set_signature_md}), the digest of RSA-OAEP ({@code
 * EVP_PKEY_CTX_set_rsa_oaep_md}, {@code EVP_PKEY_CTX_set_rsa_oaep_md_name}) and the digest of its
 * mask generation function ({@code EVP_PKEY_CTX_set_rsa_mgf1_md}), also for RSA-PSS.
 */
class OpenSSLKeyContextDigestsTest {

    @AfterEach
    void resetSharedState() {
        CxxAggregator.reset();
    }

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/keygen/OpenSSLKeyContextDigestsTestFile.cc",
                new CxxInventoryRule());

        final List<INode> keys = CxxAggregator.getDetectedNodes();
        assertThat(keys).hasSize(4);
        assertThat(child(keys.get(0), Signature.class).flatMap(s -> digest(s))).contains("SHA-384");

        final INode oaep =
                child(keys.get(1), PublicKeyEncryption.class)
                        .flatMap(pke -> child(pke, Padding.class))
                        .orElseThrow();
        assertThat(oaep.asString()).isEqualTo("OAEP");
        assertThat(digest(oaep)).contains("SHA-256");
        assertThat(child(oaep, MaskGenerationFunction.class).flatMap(mgf -> digest(mgf)))
                .contains("SHA-1");

        assertThat(
                        child(keys.get(2), PublicKeyEncryption.class)
                                .flatMap(pke -> child(pke, Padding.class))
                                .flatMap(padding -> digest(padding)))
                .contains("SHA-512");

        final INode pss = child(keys.get(3), ProbabilisticSignatureScheme.class).orElseThrow();
        assertThat(digest(pss)).contains("SHA-256");
        assertThat(child(pss, MaskGenerationFunction.class).flatMap(mgf -> digest(mgf)))
                .contains("SHA-384");
    }

    @Nonnull
    private static Optional<INode> child(
            @Nonnull INode node, @Nonnull Class<? extends INode> kind) {
        return node.hasChildOfType(kind);
    }

    @Nonnull
    private static Optional<String> digest(@Nonnull INode node) {
        return node.hasChildOfType(MessageDigest.class).map(INode::asString);
    }
}
