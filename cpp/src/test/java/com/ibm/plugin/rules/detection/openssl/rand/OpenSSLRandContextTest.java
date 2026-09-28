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
package com.ibm.plugin.rules.detection.openssl.rand;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.context.PRNGContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
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
 * A DRBG fetched by name gets the cipher or digest that is set on the context created from it,
 * whether it is passed to {@code EVP_RAND_CTX_set_params} or to {@code EVP_RAND_instantiate}.
 */
class OpenSSLRandContextTest extends TestBase {

    private final List<String> drbgs = new ArrayList<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/rand/OpenSSLRandContextTestFile.cc", this);
        assertThat(drbgs).containsExactly("CTR-DRBG AES-256-CTR", "HMAC-DRBG SHA-256", "SEED-SRC");
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
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(PRNGContext.class);
        assertThat(nodes).hasSize(1);
        INode drbg = nodes.get(0);
        INode primitive = drbg.getChildren().get(BlockCipher.class);
        if (primitive == null) {
            primitive = drbg.getChildren().get(MessageDigest.class);
        }
        drbgs.add(drbg.asString() + (primitive == null ? "" : " " + primitive.asString()));
    }
}
