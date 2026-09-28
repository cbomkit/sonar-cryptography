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
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
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
 * A KDF fetched by name gets the digest that is set on the context created from it, whether the
 * digest is passed to {@code EVP_KDF_CTX_set_params} or to {@code EVP_KDF_derive}, and whether the
 * fetched KDF is held in a variable or passed directly to {@code EVP_KDF_CTX_new}.
 */
class OpenSSLEvpKdfContextTest extends TestBase {

    private final List<String> kdfs = new ArrayList<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/kdf/OpenSSLEvpKdfContextTestFile.cc", this);
        assertThat(kdfs)
                .containsExactly(
                        "HKDF-SHA-256",
                        "PBKDF2-SHA-512",
                        "HKDF-SHA-256",
                        "SSHKDF-SHA-512",
                        // fetched inline: each KDF gets only the digest set on its own context
                        "HKDF-SHA-384",
                        "PBKDF2");
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
        assertThat(detectionStore.getDetectionValueContext())
                .isInstanceOf(KeyDerivationFunctionContext.class);
        nodes.forEach(kdf -> kdfs.add(kdf.asString()));
    }
}
