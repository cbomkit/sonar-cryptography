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
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.junit.jupiter.api.Test;

/**
 * Comprehensive test for the DSA detection rules, covering {@code DSA}, {@code DSACng}, {@code
 * DSACryptoServiceProvider} and {@code DSAOpenSsl}.
 *
 * <p>DSA is the family where the key size matters most for a bill of materials, since a 1024-bit
 * DSA key is the whole reason to go looking. The key size is asserted in each of the forms .NET
 * offers it: as the single argument of {@code Create} and of the three constructors, as the first
 * of two arguments of {@code DSACryptoServiceProvider}, through a {@code const} field, and through
 * the {@code KeySize} property. A {@code DSAParameters} argument occupies the same position and
 * must yield no key size at all.
 *
 * <p>The methods split cleanly in two. {@code SignData} and {@code VerifyData} hash the data
 * themselves and name the hash, which is captured. {@code CreateSignature} and {@code
 * VerifySignature} take an already-computed hash and name nothing, so they must carry no digest.
 * {@code DSACryptoServiceProvider} adds {@code SignHash} and {@code VerifyHash}, which name the
 * hash as a plain string rather than a {@code HashAlgorithmName}; those are captured too.
 */
class DotNetDSATest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetDSATestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        IValue<CSharpTree> primary =
                detectionStore.getDetectionValues().stream()
                        .filter(ValueAction.class::isInstance)
                        .findFirst()
                        .orElseThrow();
        assertThat(primary.asString()).isEqualTo("DSA");

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(Signature.class);

        INode oid = node.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo("1.2.840.10040.4.1");

        switch (findingId) {
            // DSA.Create(), new DSACng(), new DSACryptoServiceProvider(), new DSAOpenSsl()
            case 0, 1, 2, 3 -> assertKeySize(node, null);
            // DSA.Create(2048)
            case 4 -> assertKeySize(node, 2048);
            // new DSACng(3072)
            case 5 -> assertKeySize(node, 3072);
            // new DSACryptoServiceProvider(1024, null): key size as the first of two arguments
            case 6 -> assertKeySize(node, 1024);
            // new DSAOpenSsl(2048)
            case 7 -> assertKeySize(node, 2048);
            // DSA.Create(ConfiguredDsaKeySize) with a const field
            case 8 -> assertKeySize(node, 3072);
            // DSA.Create(parameters): a DSAParameters value is not a key size
            case 9 -> assertKeySize(node, null);
            // dsa.KeySize = 1024
            case 10 -> assertKeySize(node, 1024);
            // dsa.SignData(data, HashAlgorithmName.SHA256)
            case 11 -> assertOperation(node, Sign.class, "SHA-256");
            // dsa.SignData(data, 0, 32, HashAlgorithmName.SHA256): hash at index three
            case 12 -> assertOperation(node, Sign.class, "SHA-256");
            // dsa.TrySignData(data, destination, HashAlgorithmName.SHA384, out bytesWritten)
            case 13 -> assertOperation(node, Sign.class, "SHA-384");
            // dsa.VerifyData(data, signature, HashAlgorithmName.SHA256)
            case 14 -> assertOperation(node, Verify.class, "SHA-256");
            // dsa.VerifyData(data, 0, 32, signature, HashAlgorithmName.SHA384)
            case 15 -> assertOperation(node, Verify.class, "SHA-384");
            // dsa.SignData(data, hashAlgorithm: HashAlgorithmName.SHA384) by keyword
            case 16 -> assertOperation(node, Sign.class, "SHA-384");
            // dsa.CreateSignature(hash): a precomputed hash, no algorithm is named
            case 17 -> assertOperation(node, Sign.class, null);
            // dsa.VerifySignature(hash, signature)
            case 18 -> assertOperation(node, Verify.class, null);
            // csp.SignHash(hash, "SHA1"): the hash named as a string
            case 19 -> assertOperation(node, Sign.class, "SHA-1");
            // csp.VerifyHash(hash, "SHA1", signature)
            case 20 -> assertOperation(node, Verify.class, "SHA-1");
            // dsa.SignData(data, algorithm) where the two callers pass different algorithms
            case 21 -> assertOperation(node, Sign.class, null);
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    /** A {@code null} expectation asserts absence, not a default. */
    private static void assertKeySize(@Nonnull INode node, @Nullable Integer expectedBits) {
        assertThat(node.asString()).isEqualTo(expectedBits == null ? "DSA" : "DSA-" + expectedBits);
        assertChild(node, KeyLength.class, expectedBits);
    }

    private static void assertOperation(
            @Nonnull INode node,
            @Nonnull Class<? extends INode> operation,
            @Nullable String expectedDigest) {
        INode operationNode = node.getChildren().get(operation);
        assertThat(operationNode)
                .as("expected an %s operation", operation.getSimpleName())
                .isNotNull();
        assertChild(operationNode, MessageDigest.class, expectedDigest);
    }
}
