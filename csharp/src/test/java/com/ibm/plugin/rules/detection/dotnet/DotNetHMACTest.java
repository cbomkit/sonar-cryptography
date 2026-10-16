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
package com.ibm.plugin.rules.detection.dotnet;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpSymbol;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.MacContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.junit.jupiter.api.Test;

/**
 * Tests for the HMAC detection rules, covering the nine {@code HMAC*} classes and {@code
 * MACTripleDES}.
 *
 * <p>The first ten cases use the parameterless constructor, which generates a random key of the
 * algorithm's own default length. There is nothing in the source to read there, so they must report
 * the algorithm and its digest and no key length.
 *
 * <p>The next four pass a key whose length the engine can read, as a literal array, through a local
 * and through a {@code readonly} field, and assert that length. The last passes a key read from the
 * environment and asserts the key length stays absent, since a guessed MAC key length would be
 * worse than none.
 */
class DotNetHMACTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetHMACTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(MacContext.class);
        IValue<CSharpTree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(Mac.class);

        switch (findingId) {
            // parameterless constructors: a random key, so no key length may be reported
            case 0 -> assertHmac(node, "HMAC-SHA-1", "SHA-1", null);
            case 1 -> assertHmac(node, "HMAC-SHA-256", "SHA-256", null);
            case 2 -> assertHmac(node, "HMAC-SHA-384", "SHA-384", null);
            case 3 -> assertHmac(node, "HMAC-SHA-512", "SHA-512", null);
            case 4 -> assertHmac(node, "HMAC-MD5", "MD5", null);
            case 5 -> assertHmac(node, "HMAC-RIPEMD", "RIPEMD-160", null);
            case 6 -> assertHmac(node, "HMAC-SHA3-256", "SHA3-256", null);
            case 7 -> assertHmac(node, "HMAC-SHA3-384", "SHA3-384", null);
            case 8 -> assertHmac(node, "HMAC-SHA3-512", "SHA3-512", null);
            // MACTripleDES is not an HMAC; it translates to Triple DES used as a MAC
            case 9 -> assertHmac(node, "DESede", null, null);
            // new HMACSHA256(new byte[32])
            case 10 -> assertHmac(node, "HMAC-SHA-256", "SHA-256", 256);
            // a byte[64] key through a local
            case 11 -> assertHmac(node, "HMAC-SHA-512", "SHA-512", 512);
            // a byte[16] key through a readonly field
            case 12 -> assertHmac(node, "HMAC-SHA-256", "SHA-256", 128);
            // new MACTripleDES(new byte[24]): a 192-bit Triple DES key
            case 13 -> assertHmac(node, "DESede192", null, 192);
            // a key read from the environment: no key length may be reported
            case 14 -> assertHmac(node, "HMAC-SHA-256", "SHA-256", null);
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    /** A {@code null} expectation asserts absence, not a default. */
    private static void assertHmac(
            @Nonnull INode node,
            @Nonnull String expectedNode,
            @Nullable String expectedDigest,
            @Nullable Integer expectedKeyBits) {
        assertThat(node.asString()).isEqualTo(expectedNode);
        assertChild(node, MessageDigest.class, expectedDigest);
        assertChild(node, KeyLength.class, expectedKeyBits);
    }
}
