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

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.algorithms.AES;
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
 * Covers the rules in {@link OpenSSLLegacyMac}. The digest passed to {@code HMAC_Init_ex}, {@code
 * HMAC_Init} or {@code HMAC}, and the cipher passed to {@code CMAC_Init}, are traced back to the
 * call that created them and attached to the MAC. The calls that create them are also reported on
 * their own, as {@link DigestContext} and {@link CipherContext} findings.
 */
class OpenSSLLegacyMacTest extends TestBase {

    private final List<String> macs = new ArrayList<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/legacy/OpenSSLLegacyMacTestFile.cc", this);
        assertThat(macs)
                .containsExactly("HMAC-SHA-256", "HMAC-SHA-256", "HMAC-SHA-256", "CMAC-AES");
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

        if (detectionStore.getDetectionValueContext() instanceof DigestContext) {
            assertThat(value.asString()).isEqualTo("SHA-256");
            assertThat(nodes).hasSize(1);
            assertThat(nodes.get(0)).isInstanceOf(MessageDigest.class);
            assertThat(nodes.get(0).asString()).isEqualTo("SHA-256");
            return;
        }

        if (detectionStore.getDetectionValueContext() instanceof CipherContext) {
            assertThat(value.asString()).isEqualTo("AES-128-CBC");
            assertThat(nodes).hasSize(1);
            assertThat(nodes.get(0)).isInstanceOf(AES.class);
            assertThat(nodes.get(0).asString()).isEqualTo("AES-128-CBC");
            return;
        }

        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(MacContext.class);
        assertThat(value).isInstanceOf(ValueAction.class);
        assertThat(nodes).hasSize(1);
        macs.add(nodes.get(0).asString());
    }
}
