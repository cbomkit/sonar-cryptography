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
import com.ibm.engine.model.context.DigestContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Covers {@code GetCertHash}, {@code GetCertHashString} and {@code TryGetCertHash}: a named hash, a
 * keyword argument, SHA-1, the parameterless forms (SHA-1 by definition) and an unknown hash.
 *
 * <p>Each call must give exactly one finding. An unknown hash gives none, so a finding with id 7
 * fails the test.
 */
class DotNetCertificateHashTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetCertificateHashTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        assertThat(nodes).hasSize(1);
        final INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(MessageDigest.class);

        switch (findingId) {
            case 0 -> assertThat(node.asString()).isEqualTo("SHA-256");
            case 1 -> assertThat(node.asString()).isEqualTo("SHA-384");
            case 2 -> assertThat(node.asString()).isEqualTo("SHA-512");
            // keyword argument
            case 3 -> assertThat(node.asString()).isEqualTo("SHA-256");
            // a weak digest is reported as written
            case 4 -> assertThat(node.asString()).isEqualTo("SHA-1");
            // GetCertHash() and GetCertHashString() are the SHA-1 thumbprint
            case 5, 6 -> assertThat(node.asString()).isEqualTo("SHA-1");
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }
}
