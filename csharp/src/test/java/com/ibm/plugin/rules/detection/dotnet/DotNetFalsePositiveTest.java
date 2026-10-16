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
import com.ibm.engine.model.BlockSize;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.Mode;
import com.ibm.engine.model.Padding;
import com.ibm.engine.model.ValueAction;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Regression test for the false positives the C# parameter-resolution rewrite fixed — see
 * DotNetFalsePositiveTestFile.cs for the exact bugs each scenario used to trigger.
 *
 * <p>Every finding here must be the plain {@code AES} detection with no additional child value:
 * before the fix, {@code aes.KeySize = externalKeySize;} (a method parameter) silently produced
 * {@code KeyLength(56)} (the 7-character parameter name's byte length in bits), {@code aes.Mode =
 * mode;} produced {@code Mode("mode")}, and a conflicting reassignment produced whichever value was
 * checked first.
 */
class DotNetFalsePositiveTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetFalsePositiveTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {

        // Every scenario is a plain `Aes.Create()` — the primary AES detection must still fire.
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);
        assertThat(primary.asString()).isEqualTo("AES");

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(BlockCipher.class);
        assertThat(node.asString()).isEqualTo("AES");

        // No child value must ever appear — this is the actual regression check.
        assertThat(getStoreOfValueType(KeySize.class, detectionStore.getChildren())).isNull();
        assertThat(getStoreOfValueType(Mode.class, detectionStore.getChildren())).isNull();
        assertThat(getStoreOfValueType(Padding.class, detectionStore.getChildren())).isNull();
        assertThat(getStoreOfValueType(BlockSize.class, detectionStore.getChildren())).isNull();
        assertThat(node.getChildren().get(KeyLength.class)).isNull();
    }
}
