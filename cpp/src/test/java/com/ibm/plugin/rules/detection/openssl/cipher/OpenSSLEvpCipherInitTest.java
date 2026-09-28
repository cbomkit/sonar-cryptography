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
package com.ibm.plugin.rules.detection.openssl.cipher;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.functionality.Decrypt;
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
 * The cipher given to {@code EVP_EncryptInit}, {@code EVP_DecryptInit} or {@code EVP_CipherInit} is
 * reported with the operation it is initialized for.
 */
class OpenSSLEvpCipherInitTest extends TestBase {

    private final List<String> operations = new ArrayList<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/cipher/OpenSSLEvpCipherInitTestFile.cc", this);
        assertThat(operations)
                .containsExactlyInAnyOrder(
                        "AES-256-GCM encrypt",
                        "ChaCha20-Poly1305 decrypt",
                        "DESede168-CBC encrypt");
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
        for (INode node : nodes) {
            if (node.hasChildOfType(Encrypt.class).isPresent()) {
                operations.add(node.asString() + " encrypt");
            } else if (node.hasChildOfType(Decrypt.class).isPresent()) {
                operations.add(node.asString() + " decrypt");
            }
        }
    }
}
