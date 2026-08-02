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
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.TestBase;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * Covers all 13 rule entries in {@link OpenSSLLegacyMac}.
 *
 * <p>Follows the deep-assert pattern documented in {@link
 * com.ibm.plugin.rules.detection.openssl.rand.OpenSSLRandTest}.
 *
 * <p>Note: {@code CxxMacContextTranslator} only translates hash-suffixed MAC names (e.g. {@code
 * HMAC-SHA256}). The bare values {@code "HMAC"} and {@code "CMAC"} emitted by the legacy rules have
 * no translator case and yield empty translated nodes — there is no INode tree to walk. The real
 * digest, when set via {@code HMAC_Init_ex}/{@code HMAC_Init}/{@code HMAC}'s {@code EVP_MD*}
 * argument, is a separate, independently traced {@link DigestContext} finding (see {@link
 * com.ibm.plugin.rules.detection.openssl.digest.OpenSSLEvpMessageDigest}). Likewise, {@code
 * CMAC_Init}'s real cipher, set via its {@code EVP_CIPHER*} argument, is a separate, independently
 * traced {@link CipherContext} finding (see {@link
 * com.ibm.plugin.rules.detection.openssl.cipher.OpenSSLEvpCipher}).
 */
class OpenSSLLegacyMacTest extends TestBase {

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/legacy/OpenSSLLegacyMacTestFile.cc", this);
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

        switch (value.asString()) {
            // "HMAC" itself has no translator case (see class docstring), but a call with a
            // traced digest (HMAC_Init_ex/HMAC_Init/HMAC) carries that digest's translated
            // MessageDigest as a nested child; calls without one (HMAC_CTX_new, HMAC_Update, ...)
            // have no children at all.
            case "HMAC" ->
                    assertThat(nodes)
                            .allSatisfy(n -> assertThat(n).isInstanceOf(MessageDigest.class));
            // "CMAC" similarly nests CMAC_Init's traced cipher (BlockCipher) as a child; calls
            // without one have no children at all.
            case "CMAC" ->
                    assertThat(nodes)
                            .allSatisfy(n -> assertThat(n).isInstanceOf(BlockCipher.class));
            default -> throw new AssertionError("Unexpected value: " + value.asString());
        }
    }
}
