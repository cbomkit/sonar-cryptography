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
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.functionality.Generate;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.junit.jupiter.api.Test;

/**
 * Comprehensive test for the ECDH detection rules, covering {@code ECDiffieHellman}, {@code
 * ECDiffieHellmanCng} and {@code ECDiffieHellmanOpenSsl}.
 *
 * <p>The creation calls are read exactly as the ECDSA ones are, by value out of a single argument
 * position that .NET fills with an {@code int}, an {@code ECCurve}, an {@code ECParameters}, a
 * {@code string} or a {@code CngKey}, so the cases below assert a curve, a key length, or the
 * absence of both.
 *
 * <p>Of the five derive methods only {@code DeriveKeyFromHash} and {@code DeriveKeyFromHmac} name a
 * hash, and that hash is the derivation's pseudo-random function, so it is attached to the key
 * derivation action. {@code DeriveKeyMaterial}, {@code DeriveKeyTls} and {@code
 * DeriveRawSecretAgreement} name none and must carry no digest.
 */
class DotNetECDiffieHellmanTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetECDiffieHellmanTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);
        assertThat(primary.asString()).isEqualTo("ECDH");

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(KeyAgreement.class);
        assertThat(node.asString()).isEqualTo("ECDH");

        INode oid = node.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo("1.3.132.1.12");

        switch (findingId) {
            // ECDiffieHellman.Create()
            case 0 -> assertEcdh(node, null, null);
            // ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256)
            case 1 -> assertEcdh(node, "nistP256", null);
            // new ECDiffieHellmanCng() / new ECDiffieHellmanOpenSsl()
            case 2, 3 -> assertEcdh(node, null, null);
            // ecdh.KeySize = 256 / = 384
            case 4 -> assertEcdh(node, null, 256);
            case 5 -> assertEcdh(node, null, 384);
            // DeriveKeyMaterial(other): names no hash
            case 6 -> assertDerivation(node, null);
            // DeriveKeyFromHash(other, HashAlgorithmName.SHA256)
            case 7 -> assertDerivation(node, "SHA-256");
            // DeriveKeyFromHmac(other, HashAlgorithmName.SHA256, hmacKey)
            case 8 -> assertDerivation(node, "SHA-256");
            // DeriveKeyTls(other, prfLabel, prfSeed): names no hash
            case 9 -> assertDerivation(node, null);
            // DeriveRawSecretAgreement(other): a raw agreement, no derivation at all
            case 10 -> assertThat(node.getChildren().get(Generate.class)).isNotNull();
            // ECDiffieHellmanCng full flow: KeySize 384 plus a derivation
            case 11 -> {
                assertEcdh(node, null, 384);
                assertDerivation(node, null);
            }
            // ECDiffieHellmanOpenSsl derive flow
            case 12 -> assertDerivation(node, "SHA-256");
            // ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384)
            case 13 -> assertEcdh(node, "nistP384", null);
            // new ECDiffieHellmanCng(521)
            case 14 -> assertEcdh(node, null, 521);
            // ECDiffieHellman.Create(ECCurve.CreateFromFriendlyName("secp384r1"))
            case 15 -> assertEcdh(node, "secp384r1", null);
            // ECDiffieHellman.Create(parameters): neither curve nor key size
            case 16 -> assertEcdh(node, null, null);
            // DeriveKeyFromHash(other, SHA512, secretPrepend, secretAppend)
            case 17 -> assertDerivation(node, "SHA-512");
            // DeriveKeyFromHmac(other, hmacKey: ..., hashAlgorithm: SHA384) by keyword
            case 18 -> assertDerivation(node, "SHA-384");
            // DeriveKeyFromHash(other, algorithm) where the callers disagree on algorithm
            case 19 -> assertDerivation(node, null);
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    /** A {@code null} expectation asserts absence, not a default. */
    private static void assertEcdh(
            @Nonnull INode node,
            @Nullable String expectedCurve,
            @Nullable Integer expectedKeyBits) {
        assertChild(node, EllipticCurve.class, expectedCurve);
        assertChild(node, KeyLength.class, expectedKeyBits);
    }

    private static void assertDerivation(@Nonnull INode node, @Nullable String expectedDigest) {
        INode derivation = node.getChildren().get(KeyDerivation.class);
        assertThat(derivation).as("expected a key derivation action").isNotNull();
        assertChild(derivation, MessageDigest.class, expectedDigest);
    }
}
