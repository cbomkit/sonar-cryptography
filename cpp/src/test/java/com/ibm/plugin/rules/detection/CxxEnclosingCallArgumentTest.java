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

import com.ibm.engine.detection.DetectionStore;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.TestBase;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * A call passed as an argument to a detected call that reports it, such as {@code
 * EVP_aes_256_gcm()} in {@code EVP_EncryptInit_ex}, is reported once, with that call. A call used
 * on its own, or passed to a call no rule detects, is reported on its own.
 */
class CxxEnclosingCallArgumentTest extends TestBase {

    private final List<String> findings = new ArrayList<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/CxxEnclosingCallArgumentTestFile.cc", this);
        assertThat(findings)
                .containsExactly(
                        "AuthenticatedEncryption:AES-256-GCM [Encrypt]",
                        "MessageDigest:SHA-256",
                        "MessageDigest:SHA-384");
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
        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        String description = node.getKind().getSimpleName() + ":" + node.asString();
        if (node.hasChildOfType(Encrypt.class).isPresent()) {
            description += " [Encrypt]";
        }
        findings.add(description);
    }
}
