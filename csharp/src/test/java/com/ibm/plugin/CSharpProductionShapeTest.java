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
package com.ibm.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpSymbol;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.NonceLength;
import com.ibm.mapper.model.NumberOfIterations;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Verify;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Runs the rule set over the constructs that defeated it when it was pointed at real .NET code, so
 * that each stays fixed.
 *
 * <p>The fixture reproduces shapes from ASP.NET Core's Data Protection stack and the Bitwarden
 * server rather than vendoring their source. The shapes are the ordinary ones of production
 * cryptography code, and each was a genuine miss: the entire file sits inside a {@code #if} region,
 * which the grammar skips, so before {@link CSharpConditionalDirectives} two of the three
 * cryptography-bearing Data Protection files produced nothing at all. Around that are a file-scoped
 * namespace, {@code internal sealed unsafe} classes, a pinned buffer, a {@code stackalloc} span,
 * sizes held in {@code const} fields, a {@code using} declaration inside a {@code for} loop, and a
 * signing key obtained from a certificate.
 */
class CSharpProductionShapeTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/CSharpProductionShapeTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);

        switch (findingId) {
            // new AesGcm(derivedKey, TAG_SIZE_IN_BYTES) inside a fixed block, with the key size
            // from a const field and the tag size from another
            case 0 -> {
                assertThat(node.asString()).isEqualTo("AES-256");
                assertChild(node, KeyLength.class, 256);
                assertChild(node, TagLength.class, 128);
                INode decrypt = node.getChildren().get(Decrypt.class);
                assertThat(decrypt).isNotNull();
                assertChild(decrypt, NonceLength.class, 96);
                assertChild(decrypt, TagLength.class, 128);
            }
            // Rfc2898DeriveBytes.Pbkdf2(password, salt, IterationCount, SHA256, DerivedKeyBytes)
            case 1 -> {
                assertThat(node.asString()).isEqualTo("PBKDF2-SHA-256");
                assertChild(node, MessageDigest.class, "SHA-256");
                assertChild(node, NumberOfIterations.class, 100000);
                assertChild(node, SaltLength.class, 128);
                assertChild(node, KeyLength.class, 256);
            }
            // using var rsa = RSA.Create(2048) inside a for loop, then SignData with SHA-256/PKCS1
            case 2 -> {
                assertThat(node.asString()).isEqualTo("RSA-2048");
                assertChild(node, KeyLength.class, 2048);
                INode sign = node.getChildren().get(Sign.class);
                assertThat(sign).isNotNull();
                assertChild(sign, MessageDigest.class, "SHA-256");
                assertChild(sign, Padding.class, "PKCS1");
            }
            // certificate.GetRSAPublicKey() then VerifyData with SHA-256/PKCS1
            case 3 -> {
                assertThat(node.asString()).isEqualTo("RSA");
                INode verify = node.getChildren().get(Verify.class);
                assertThat(verify).isNotNull();
                assertChild(verify, MessageDigest.class, "SHA-256");
                assertChild(verify, Padding.class, "PKCS1");
            }
            // RandomNumberGenerator.Fill(stackalloc byte[32])
            case 4 -> {
                assertThat(node.asString()).isEqualTo("NATIVEPRNG");
                assertChild(node, KeyLength.class, 256);
            }
            // RSA.Create(4096) plus SignData after a conditional that splits one expression
            // across its branches. Before the parse fallback this produced nothing at all, because
            // the broken region cost the rest of the file.
            case 5 -> {
                assertThat(node.asString()).isEqualTo("RSA-4096");
                assertChild(node, KeyLength.class, 4096);
                INode sign = node.getChildren().get(Sign.class);
                assertThat(sign).isNotNull();
                assertChild(sign, MessageDigest.class, "SHA-512");
                assertChild(sign, Padding.class, "PSS");
            }
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }
}
