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
import com.ibm.engine.model.context.CipherContext;
import com.ibm.mapper.model.INode;
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
 * Cipher names passed to {@code EVP_CIPHER_fetch} and {@code EVP_get_cipherbyname} are matched
 * case-insensitively and may be OpenSSL aliases.
 */
class OpenSSLEvpCipherFetchNamesTest extends TestBase {

    private final List<String> ciphers = new ArrayList<>();

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/cipher/OpenSSLEvpCipherFetchNamesTestFile.cc", this);
        assertThat(ciphers)
                .containsExactly(
                        "AES-256-GCM",
                        "AES-128-CBC",
                        "AES-256-GCM",
                        "AES-256-CBC",
                        "DESede168-CBC",
                        "ChaCha20-Poly1305",
                        "DESede168-CBC",
                        "Blowfish-128-CBC");
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
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(nodes).hasSize(1);
        ciphers.add(nodes.get(0).asString());
    }
}
