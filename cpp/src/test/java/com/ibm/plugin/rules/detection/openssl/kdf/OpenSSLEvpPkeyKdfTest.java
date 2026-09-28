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
package com.ibm.plugin.rules.detection.openssl.kdf;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.mapper.model.IAlgorithm;
import com.ibm.mapper.model.INode;
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

/** A KDF selected through the EVP_PKEY interface gets the digest that is set on its context. */
class OpenSSLEvpPkeyKdfTest extends TestBase {

    private final List<String> assets = new ArrayList<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/kdf/OpenSSLEvpPkeyKdfTestFile.cc", this);
        assertThat(assets)
                .containsExactly(
                        "KeyDerivationFunction:HKDF-SHA-256 [MessageDigest:SHA-256]",
                        "MessageDigest:SHA-256",
                        "KeyDerivationFunction:TLS-PRF-SHA-384 [MessageDigest:SHA-384]",
                        "MessageDigest:SHA-384",
                        "PasswordBasedKeyDerivationFunction:scrypt");
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

    /** The kind and name of the node, followed by the kinds and names of its algorithm children. */
    @Nonnull
    private static String describe(@Nonnull INode node) {
        final String children =
                node.getChildren().values().stream()
                        .filter(IAlgorithm.class::isInstance)
                        .map(child -> child.getKind().getSimpleName() + ":" + child.asString())
                        .sorted()
                        .collect(Collectors.joining(", "));
        final String self = node.getKind().getSimpleName() + ":" + node.asString();
        return children.isEmpty() ? self : self + " [" + children + "]";
    }
}
