/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
package com.ibm.plugin.rules.detection.openssl.cms;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.mapper.model.IAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.functionality.Functionality;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.TestBase;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * The CMS and PKCS#7 encryption functions report their content encryption cipher with the encrypt
 * operation, a CMS KEK recipient reports its key wrap algorithm, the time-stamping signer digest
 * given by name, the RSA-PSS salt length and the CRMF password-based MAC are reported, and the
 * digest passed to a CMS, PKCS#7 or OCSP signing function is reported once, by the digest rules.
 */
class OpenSSLCmsTest extends TestBase {

    private final List<String> assets = new ArrayList<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/cms/OpenSSLCmsTestFile.cc", this);
        assertThat(assets)
                .containsExactly(
                        "BlockCipher:AES-256-CBC [Encrypt:ENCRYPT]",
                        "BlockCipher:AES-256-CBC",
                        "AuthenticatedEncryption:AES-128-GCM",
                        "AuthenticatedEncryption:AES-128-GCM [Encrypt:ENCRYPT]",
                        "BlockCipher:AES-256-WRAP",
                        "BlockCipher:DESede168-CBC [Encrypt:ENCRYPT]",
                        "BlockCipher:DESede168-CBC",
                        "MessageDigest:SHA-384 [Digest:DIGEST]",
                        "MessageDigest:SHA-256 [Digest:DIGEST]",
                        "MessageDigest:SHA-1 [Digest:DIGEST]",
                        "ProbabilisticSignatureScheme:RSA-PSS [SaltLength:256]",
                        "ProbabilisticSignatureScheme:RSA-PSS",
                        "MessageDigest:SHA-256 [Digest:DIGEST]",
                        "MessageDigest:SHA-512 [Digest:DIGEST]",
                        "Mac:HMAC-SHA-1 [MessageDigest:SHA-1, Tag:TAG]",
                        "MessageDigest:SHA-256 [Digest:DIGEST]");
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
        nodes.forEach(node -> assets.add(describe(node)));
    }

    /**
     * The kind and name of the node, followed by the kinds and names of its algorithm, operation
     * and salt length children.
     */
    @Nonnull
    private static String describe(@Nonnull INode node) {
        final String children =
                node.getChildren().values().stream()
                        .filter(
                                child ->
                                        child instanceof IAlgorithm
                                                || child instanceof Functionality
                                                || child instanceof SaltLength)
                        .map(child -> child.getKind().getSimpleName() + ":" + child.asString())
                        .sorted()
                        .collect(Collectors.joining(", "));
        final String self = node.getKind().getSimpleName() + ":" + node.asString();
        return children.isEmpty() ? self : self + " [" + children + "]";
    }
}
