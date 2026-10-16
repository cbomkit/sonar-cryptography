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
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.junit.jupiter.api.Test;

/**
 * Comprehensive test for the ECDSA detection rules, covering {@code ECDsa}, {@code ECDsaCng} and
 * {@code ECDsaOpenSsl}.
 *
 * <p>Three things are being proved here beyond the plain presence of the algorithm.
 *
 * <p>The single argument of {@code Create} and of the two derived constructors is read by value,
 * because .NET puts an {@code int} key size, an {@code ECCurve}, an {@code ECParameters}, a {@code
 * string} provider name and a {@code CngKey} in that one position. The cases below assert a key
 * length for the {@code int} form, a curve for the {@code ECCurve} forms, and nothing at all for
 * {@code ECParameters} and {@code CngKey}.
 *
 * <p>The {@code HashAlgorithmName} of a signing call is attached to the sign or verify action. Its
 * position varies by overload, from index one in {@code SignData(data, hashAlgorithm)} to index
 * three in {@code SignData(data, offset, count, hashAlgorithm)} and index four in the corresponding
 * {@code VerifyData}, so these cases also prove the argument is found by type rather than by
 * position. {@code SignHash} and {@code VerifyHash} take an already-computed hash and name no
 * algorithm, so they must carry no digest.
 *
 * <p>Two cases must resolve to nothing: an {@code ECParameters} argument, and a {@code
 * HashAlgorithmName} arriving as a method parameter whose two callers pass different values.
 *
 * <p>{@code ECDSA.asString()} appends only a curve or digest suffix, following the CycloneDX
 * pattern {@code ECDSA[-{ellipticCurve}][-{hashAlgorithm}]}, which has no key length placeholder. A
 * detected key size therefore shows up as a {@link KeyLength} child without changing the name.
 */
class DotNetECDsaTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetECDsaTestFile.cs", this);
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
            // ECDsa.Create()
            case 0 -> assertEcdsa(node, "ECDSA", null, null);
            // ECDsa.Create(ECCurve.NamedCurves.nistP256)
            case 1 -> assertEcdsa(node, "ECDSA-nistP256", "nistP256", null);
            // new ECDsaCng()
            case 2 -> assertEcdsa(node, "ECDSA", null, null);
            // new ECDsaOpenSsl()
            case 3 -> assertEcdsa(node, "ECDSA", null, null);
            // new ECDsaCng(cngKey): a CngKey is neither a curve nor a key size
            case 4 -> assertEcdsa(node, "ECDSA", null, null);
            // new ECDsaCng(ECCurve.NamedCurves.nistP521)
            case 5 -> assertEcdsa(node, "ECDSA-nistP521", "nistP521", null);
            // new ECDsaCng(521)
            case 6 -> assertEcdsa(node, "ECDSA", null, 521);
            // ecdsa.KeySize = 256
            case 7 -> assertEcdsa(node, "ECDSA", null, 256);
            // ecdsa.KeySize = 384
            case 8 -> assertEcdsa(node, "ECDSA", null, 384);
            // ecdsa.SignData(data, HashAlgorithmName.SHA256)
            case 9 -> assertSignature(node, Sign.class, "SHA-256");
            // ecdsa.TrySignData(data, destination, HashAlgorithmName.SHA256, out bytesWritten)
            case 10 -> assertSignature(node, Sign.class, "SHA-256");
            // ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256)
            case 11 -> assertSignature(node, Verify.class, "SHA-256");
            // ecdsa.SignHash(hash): a precomputed hash, no algorithm is named
            case 12 -> assertSignature(node, Sign.class, null);
            // ecdsa.TrySignHash(hash, destination, out bytesWritten)
            case 13 -> assertSignature(node, Sign.class, null);
            // ecdsa.VerifyHash(hash, signature)
            case 14 -> assertSignature(node, Verify.class, null);
            // new ECDsaCng(); KeySize = 384; SignData(data, SHA384)
            case 15 -> {
                assertChild(node, KeyLength.class, 384);
                assertSignature(node, Sign.class, "SHA-384");
            }
            // new ECDsaOpenSsl(); VerifyData(data, signature, SHA256)
            case 16 -> assertSignature(node, Verify.class, "SHA-256");
            // SignData(data, 0, 32, HashAlgorithmName.SHA512): hash at index three
            case 17 -> assertSignature(node, Sign.class, "SHA-512");
            // VerifyData(data, 0, 32, signature, HashAlgorithmName.SHA384): hash at index four
            case 18 -> assertSignature(node, Verify.class, "SHA-384");
            // SignData(data, hashAlgorithm: HashAlgorithmName.SHA384): hash by keyword
            case 19 -> assertSignature(node, Sign.class, "SHA-384");
            // ECDsa.Create(ECCurve.CreateFromFriendlyName("secp256k1"))
            case 20 -> assertEcdsa(node, "ECDSA-secp256k1", "secp256k1", null);
            // var curve = ECCurve.NamedCurves.nistP384; ECDsa.Create(curve)
            case 21 -> assertEcdsa(node, "ECDSA-nistP384", "nistP384", null);
            // new ECDsaOpenSsl(384)
            case 22 -> assertEcdsa(node, "ECDSA", null, 384);
            // ECDsa.Create(parameters): an ECParameters value yields neither curve nor key size
            case 23 -> assertEcdsa(node, "ECDSA", null, null);
            // SignData(data, algorithm) where algorithm is a parameter with disagreeing callers
            case 24 -> assertSignature(node, Sign.class, null);
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    /** A {@code null} expectation asserts absence, not a default. */
    private static void assertEcdsa(
            @Nonnull INode node,
            @Nonnull String expectedName,
            @Nullable String expectedCurve,
            @Nullable Integer expectedKeyBits) {
        assertThat(node.asString()).isEqualTo(expectedName);
        assertChild(node, EllipticCurve.class, expectedCurve);
        assertChild(node, KeyLength.class, expectedKeyBits);
    }

    /**
     * Asserts that the ECDSA node carries the given signing action and that the action carries, or
     * deliberately lacks, a digest.
     */
    private static void assertSignature(
            @Nonnull INode node,
            @Nonnull Class<? extends INode> action,
            @Nullable String expectedDigest) {
        assertThat(node.asString()).isEqualTo("ECDSA");
        INode actionNode = node.getChildren().get(action);
        assertThat(actionNode).as("expected a %s action", action.getSimpleName()).isNotNull();
        assertChild(actionNode, MessageDigest.class, expectedDigest);
    }
}
