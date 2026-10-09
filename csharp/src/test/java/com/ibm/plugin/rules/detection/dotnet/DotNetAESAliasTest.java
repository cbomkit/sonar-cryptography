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
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.Mode;
import com.ibm.engine.model.Padding;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Verifies that property-setter assignments on an aliased variable are correctly linked back to the
 * primary detection.
 *
 * <p>Test scenario (from ProbeCSharpAliasTestFile.cs):
 *
 * <pre>{@code
 * var aes = Aes.Create();
 * var alias = aes;
 * alias.Mode = CipherMode.CBC;
 * alias.KeySize = 256;
 * }</pre>
 *
 * <p>When {@code alias} is used for property setters, the engine should resolve the alias back to
 * {@code aes} and link the property values (Mode, KeySize) to the original detection.
 */
class DotNetAESAliasTest extends TestBase {

    @Test
    void testAlias() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/ProbeCSharpAliasTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {

        switch (findingId) {
            case 0 -> {
                /*
                 * TestViaAlias: var aes = Aes.Create() + alias = aes + alias.Mode/KeySize setters
                 * Expected: AES-256-CBC (Mode=CBC, KeySize=256)
                 */

                // Primary detection: AES
                assertThat(detectionStore.getDetectionValues()).hasSize(1);
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(CipherContext.class);
                IValue<CSharpTree> primaryValue = detectionStore.getDetectionValues().get(0);
                assertThat(primaryValue).isInstanceOf(ValueAction.class);
                assertThat(primaryValue.asString()).isEqualTo("AES");

                // Depending rule: set_Mode detected Mode("CBC")
                DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> modeStore =
                        getStoreOfValueType(Mode.class, detectionStore.getChildren());
                assertThat(modeStore).isNotNull();
                assertThat(modeStore.getDetectionValues()).hasSize(1);
                assertThat(modeStore.getDetectionValues().get(0).asString()).isEqualTo("CBC");

                // Depending rule: set_KeySize detected KeySize(256)
                DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                        keySizeStore =
                                getStoreOfValueType(KeySize.class, detectionStore.getChildren());
                assertThat(keySizeStore).isNotNull();
                assertThat(keySizeStore.getDetectionValues()).hasSize(1);
                assertThat(keySizeStore.getDetectionValues().get(0).asString()).isEqualTo("256");

                // No Padding setter was called, so Padding should not be detected
                DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                        paddingStore =
                                getStoreOfValueType(Padding.class, detectionStore.getChildren());
                assertThat(paddingStore).isNull();

                // Translation: BlockCipher node
                assertThat(nodes).hasSize(1);
                INode node = nodes.get(0);
                assertThat(node.getKind()).isEqualTo(BlockCipher.class);
                assertThat(node.asString()).isEqualTo("AES-256-CBC");
                INode keyLength = node.getChildren().get(KeyLength.class);
                assertThat(keyLength).isNotNull();
                assertThat(keyLength.asString()).isEqualTo("256");
            }

            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }
}
