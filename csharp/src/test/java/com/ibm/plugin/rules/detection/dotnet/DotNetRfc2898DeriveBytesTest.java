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
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

class DotNetRfc2898DeriveBytesTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetRfc2898DeriveBytesTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);
        assertThat(primary.asString()).isEqualTo("PBKDF2");

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(PasswordBasedKeyDerivationFunction.class);
        assertThat(node.asString()).isEqualTo("PBKDF2");

        switch (findingId) {
            // 0: new Rfc2898DeriveBytes(...) alone — no operations called afterwards
            case 0 -> assertThat(node.getChildren()).isEmpty();
            // 1: new Rfc2898DeriveBytes(...) followed by kdf.GetBytes(32)
            case 1 -> assertKeyDerivationChild(detectionStore, node);
            // 2: new Rfc2898DeriveBytes(...) followed by kdf.CryptDeriveKey(...)
            case 2 -> assertKeyDerivationChild(detectionStore, node);
            // 3: Rfc2898DeriveBytes.Pbkdf2(byte[], byte[], int, HashAlgorithmName, int) — static,
            // self-contained, no depending operations
            case 3 -> assertThat(node.getChildren()).isEmpty();
            // 4: Rfc2898DeriveBytes.Pbkdf2(string, byte[], int, HashAlgorithmName, int) — static
            case 4 -> assertThat(node.getChildren()).isEmpty();
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    private void assertKeyDerivationChild(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull INode node) {
        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> deriveStore =
                getStoreOfValueType(ValueAction.class, store.getChildren());
        assertThat(deriveStore).isNotNull();
        assertThat(deriveStore.getDetectionValues()).hasSize(1);

        assertThat(node.getChildren().get(KeyDerivation.class)).isNotNull();
        assertThat(node.getChildren().get(KeyDerivation.class).asString())
                .isEqualTo("KEYDERIVATION");
    }
}
