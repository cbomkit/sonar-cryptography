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
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.ValueAction;
import com.ibm.mapper.model.IAsset;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKey;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Verifies that a key taken from an X.509 certificate produces the algorithm finding its {@code
 * Create()}-based equivalent would, that the key's kind is recorded, and that the operations
 * performed on that key are still picked up by the algorithm's depending rules.
 *
 * <p>The key kind is the one detail these call sites state for free: {@code GetRSAPrivateKey} says
 * private, {@code GetRSAPublicKey} says public. A certificate-backed key has no resolvable length —
 * it is whatever the certificate holds — so without the kind such a finding is indistinguishable
 * from one where the engine simply failed to resolve a parameter. With it, the CBOM carries a
 * {@code private-key} or {@code public-key} related-crypto-material component whose size is
 * legitimately absent, rather than a bare algorithm that looks half-detected.
 */
class DotNetCertificateKeysTest extends TestBase {

    private final List<String> observed = new ArrayList<>();

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetCertificateKeysTestFile.cs", this);

        assertThat(observed)
                .containsExactlyInAnyOrder(
                        "PublicKey:RSA:VERIFY", // GetRSAPublicKey() + VerifyData(...)
                        "PrivateKey:RSA:SIGN", // GetRSAPrivateKey() + SignData(...)
                        "PrivateKey:ECDSA:-",
                        "PublicKey:ECDSA:-",
                        "PublicKey:DSA:-",
                        "PrivateKey:DSA:-",
                        "PrivateKey:ECDH:-",
                        "PublicKey:ECDH:-",
                        // RSACertificateExtensions.GetRSAPublicKey(cert) — static spelling
                        "PublicKey:RSA:-",
                        // ECDsaCertificateExtensions.GetECDsaPrivateKey(cert) into ECDsa?
                        "PrivateKey:ECDSA:-");
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        String algorithm =
                detectionStore.getDetectionValues().stream()
                        .filter(ValueAction.class::isInstance)
                        .map(value -> value.asString())
                        .findFirst()
                        .orElseThrow();
        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> signatureStore =
                getStoreOfValueType(SignatureAction.class, detectionStore.getChildren());
        String operation =
                signatureStore == null
                        ? "-"
                        : signatureStore.getDetectionValues().get(0).asString();
        assertThat(nodes).hasSize(1);
        final INode keyNode = nodes.get(0);
        // The node must be the concrete key kind, never a bare Key: the CycloneDX builder maps a
        // plain Key to secret-key, which would file an asymmetric key under symmetric material.
        assertThat(keyNode.is(PrivateKey.class) || keyNode.is(PublicKey.class))
                .as("node %s must be a PrivateKey or a PublicKey", keyNode.getKind())
                .isTrue();
        assertThat(keyNode.asString()).isEqualTo(algorithm);
        // The algorithm is kept as a child of the key, so the CBOM still gets its own algorithm
        // component below the key material rather than losing it to the wrapper.
        assertThat(keyNode.getChildren().values().stream().anyMatch(IAsset.class::isInstance))
                .as("key %s must keep the algorithm as a child", keyNode.asString())
                .isTrue();

        observed.add(keyNode.getKind().getSimpleName() + ":" + algorithm + ":" + operation);
    }
}
