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
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link DotNetHMAC}.
 *
 * <p>findingId → test method → expected translated node ({@code asString()}), in source order of
 * {@code DotNetHMACTestFile.cs}:
 *
 * <ul>
 *   <li>0 → {@code TestHmacSha1} → {@code HMAC-SHA-1}
 *   <li>1 → {@code TestHmacSha256} → {@code HMAC-SHA-256}
 *   <li>2 → {@code TestHmacSha384} → {@code HMAC-SHA-384}
 *   <li>3 → {@code TestHmacSha512} → {@code HMAC-SHA-512}
 *   <li>4 → {@code TestHmacMd5} → {@code HMAC-MD5}
 *   <li>5 → {@code TestHmacRipemd160} → {@code HMAC-RIPEMD} (digest child: {@code RIPEMD-160})
 *   <li>6 → {@code TestHmacSha3_256} → {@code HMAC-SHA3-256}
 *   <li>7 → {@code TestHmacSha3_384} → {@code HMAC-SHA3-384}
 *   <li>8 → {@code TestHmacSha3_512} → {@code HMAC-SHA3-512}
 *   <li>9 → {@code TestMacTripleDes} → {@code DESede} (not an HMAC(digest) node; see {@link
 *       DotNetHMAC} javadoc for why {@code MACTripleDES} is modeled as DESede-as-Mac)
 * </ul>
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

        /*
         * Detection Store
         */
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(MacContext.class);
        IValue<CSharpTree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(Mac.class);

        switch (findingId) {
            case 0 -> {
                assertThat(value0.asString()).isEqualTo("HMACSHA1");
                assertThat(node.asString()).isEqualTo("HMAC-SHA-1");
                INode digest = node.getChildren().get(MessageDigest.class);
                assertThat(digest).isNotNull();
                assertThat(digest.asString()).isEqualTo("SHA-1");
                INode digestSize = digest.getChildren().get(DigestSize.class);
                assertThat(digestSize).isNotNull();
                assertThat(digestSize.asString()).isEqualTo("160");
            }
            case 1 -> {
                assertThat(value0.asString()).isEqualTo("HMACSHA256");
                assertThat(node.asString()).isEqualTo("HMAC-SHA-256");
                INode digest = node.getChildren().get(MessageDigest.class);
                assertThat(digest).isNotNull();
                assertThat(digest.asString()).isEqualTo("SHA-256");
                INode digestSize = digest.getChildren().get(DigestSize.class);
                assertThat(digestSize).isNotNull();
                assertThat(digestSize.asString()).isEqualTo("256");
            }
            case 2 -> {
                assertThat(value0.asString()).isEqualTo("HMACSHA384");
                assertThat(node.asString()).isEqualTo("HMAC-SHA-384");
                INode digest = node.getChildren().get(MessageDigest.class);
                assertThat(digest).isNotNull();
                assertThat(digest.asString()).isEqualTo("SHA-384");
                INode digestSize = digest.getChildren().get(DigestSize.class);
                assertThat(digestSize).isNotNull();
                assertThat(digestSize.asString()).isEqualTo("384");
            }
            case 3 -> {
                assertThat(value0.asString()).isEqualTo("HMACSHA512");
                assertThat(node.asString()).isEqualTo("HMAC-SHA-512");
                INode digest = node.getChildren().get(MessageDigest.class);
                assertThat(digest).isNotNull();
                assertThat(digest.asString()).isEqualTo("SHA-512");
                INode digestSize = digest.getChildren().get(DigestSize.class);
                assertThat(digestSize).isNotNull();
                assertThat(digestSize.asString()).isEqualTo("512");
            }
            case 4 -> {
                assertThat(value0.asString()).isEqualTo("HMACMD5");
                assertThat(node.asString()).isEqualTo("HMAC-MD5");
                INode digest = node.getChildren().get(MessageDigest.class);
                assertThat(digest).isNotNull();
                assertThat(digest.asString()).isEqualTo("MD5");
                INode digestSize = digest.getChildren().get(DigestSize.class);
                assertThat(digestSize).isNotNull();
                assertThat(digestSize.asString()).isEqualTo("128");
            }
            case 5 -> {
                assertThat(value0.asString()).isEqualTo("HMACRIPEMD160");
                assertThat(node.asString()).isEqualTo("HMAC-RIPEMD");
                INode digest = node.getChildren().get(MessageDigest.class);
                assertThat(digest).isNotNull();
                assertThat(digest.asString()).isEqualTo("RIPEMD-160");
                INode digestSize = digest.getChildren().get(DigestSize.class);
                assertThat(digestSize).isNotNull();
                assertThat(digestSize.asString()).isEqualTo("160");
            }
            case 6 -> {
                assertThat(value0.asString()).isEqualTo("HMACSHA3_256");
                assertThat(node.asString()).isEqualTo("HMAC-SHA3-256");
                INode digest = node.getChildren().get(MessageDigest.class);
                assertThat(digest).isNotNull();
                assertThat(digest.asString()).isEqualTo("SHA3-256");
                INode digestSize = digest.getChildren().get(DigestSize.class);
                assertThat(digestSize).isNotNull();
                assertThat(digestSize.asString()).isEqualTo("256");
            }
            case 7 -> {
                assertThat(value0.asString()).isEqualTo("HMACSHA3_384");
                assertThat(node.asString()).isEqualTo("HMAC-SHA3-384");
                INode digest = node.getChildren().get(MessageDigest.class);
                assertThat(digest).isNotNull();
                assertThat(digest.asString()).isEqualTo("SHA3-384");
                INode digestSize = digest.getChildren().get(DigestSize.class);
                assertThat(digestSize).isNotNull();
                assertThat(digestSize.asString()).isEqualTo("384");
            }
            case 8 -> {
                assertThat(value0.asString()).isEqualTo("HMACSHA3_512");
                assertThat(node.asString()).isEqualTo("HMAC-SHA3-512");
                INode digest = node.getChildren().get(MessageDigest.class);
                assertThat(digest).isNotNull();
                assertThat(digest.asString()).isEqualTo("SHA3-512");
                INode digestSize = digest.getChildren().get(DigestSize.class);
                assertThat(digestSize).isNotNull();
                assertThat(digestSize.asString()).isEqualTo("512");
            }
            case 9 -> {
                // MACTripleDES is not HMAC-based: it translates to the DESede algorithm
                // reinterpreted "as" a Mac (see DotNetHMAC javadoc), not to an HMAC(digest) node.
                assertThat(value0.asString()).isEqualTo("MACTRIPLEDES");
                assertThat(node.asString()).isEqualTo("DESede");
                INode blockSize = node.getChildren().get(BlockSize.class);
                assertThat(blockSize).isNotNull();
                assertThat(blockSize.asString()).isEqualTo("64");
            }
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }
}
