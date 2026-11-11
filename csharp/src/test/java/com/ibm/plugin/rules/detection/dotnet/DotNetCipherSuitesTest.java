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
package com.ibm.plugin.rules.detection.dotnet;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpSymbol;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * The cipher suites a .NET application allows, read from {@code CipherSuitesPolicy}.
 *
 * <p>This is the only .NET API that names suites directly, and the point of the test is that the
 * name goes all the way: {@code TlsCipherSuite.TLS_AES_256_GCM_SHA384} arrives as the key exchange,
 * cipher and digest it is made of, not as a string. Reading it at all needed the C# engine to stop
 * resolving a braced initializer to its element count, so the multi-element cases are also the
 * regression test for that change.
 *
 * <p>Three counter-checks: a list taken from a parameter, a member of an unrelated enum, and an
 * unrelated constructor of the same arity. None may produce a suite.
 */
class DotNetCipherSuitesTest extends TestBase {

    private final List<String> found = new ArrayList<>();

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetCipherSuitesTestFile.cs", this);
        assertThat(found)
                .as("every suite the policy allows, resolved through the IANA table")
                .containsExactly(
                        "TLS=TLS[CipherSuite=TLS_AES_256_GCM_SHA384[AssetCollection=[AES-256-GCM,"
                                + " SHA-384], IdentifierCollection=[0x13, 0x02]]]",
                        "TLS=TLS[CipherSuite=TLS_CHACHA20_POLY1305_SHA256[AssetCollection=[ChaCha20-Poly1305,"
                                + " SHA-256], IdentifierCollection=[0x13, 0x03]]]",
                        "TLS=TLS[CipherSuite=TLS_AES_128_GCM_SHA256[AssetCollection=[AES-128-GCM,"
                                + " SHA-256], IdentifierCollection=[0x13, 0x01]]]",
                        // The explicit element type, which used to yield the policy without its
                        // suite: the parser puts the brackets inside `type_` and the braces into a
                        // collection initializer, so `new TlsCipherSuite[] { ... }` reached the
                        // object-creation path while the implicit `new[] { ... }` above reached the
                        // array path. Both forms now read their elements.
                        "TLS=TLS[CipherSuite=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256[AssetCollection=[ECDH,"
                                + " AES-128-GCM, RSA], IdentifierCollection=[0xC0, 0x2F]]]",
                        "TLS=TLS[CipherSuite=TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384[AssetCollection=[ECDH,"
                                + " AES-256-GCM, ECDSA-SHA-384], IdentifierCollection=[0xC0, 0x2C]]]",
                        // A weak suite has to be visible as itself -- 3DES and its CBC mode.
                        "TLS=TLS[CipherSuite=TLS_RSA_WITH_3DES_EDE_CBC_SHA[AssetCollection=[RSA,"
                                + " 3DES-CBC, RSA], IdentifierCollection=[0x00, 0x0A]]]",
                        // Counter-check: the list arrives in a parameter, so no suite is knowable.
                        "TLS=TLS",
                        // Counter-check: a member of an unrelated enum. Before the registry guard
                        // in CSharpProtocolContextTranslator this became a cipher suite named
                        // TLS_SOMETHING_INVENTED.
                        "TLS=TLS");
    }

    /** Renders a node and its children as {@code Kind=value[children]}, children sorted. */
    private static String render(@Nonnull INode node) {
        String self = node.getKind().getSimpleName() + "=" + node.asString();
        List<String> children =
                node.getChildren().values().stream()
                        .map(DotNetCipherSuitesTest::render)
                        .sorted()
                        .toList();
        return children.isEmpty() ? self : self + children;
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        nodes.forEach(node -> found.add(render(node)));
    }
}
