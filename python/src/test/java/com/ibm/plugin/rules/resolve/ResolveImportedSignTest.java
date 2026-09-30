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
package com.ibm.plugin.rules.resolve;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import java.io.File;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.TestPythonVisitorRunner;

class ResolveImportedSignTest extends TestBase {

    private DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> capturedStore;
    private List<INode> capturedNodes;
    private int capturedFindingCount;

    @Test
    void test() {
        // Scan the implementation file first to register function definitions in the global registry
        TestPythonVisitorRunner.scanFile(
                new File("src/test/files/rules/resolve/imports/ResolveImportedSignImport.py"), this);

        TestPythonVisitorRunner.scanFile(
                new File("src/test/files/rules/resolve/ResolveImportedSignTestFile.py"), this);

        assertThat(capturedFindingCount).isEqualTo(1);
        assertThat(capturedStore).isNotNull();
        assertThat(capturedNodes).isNotNull();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(findingId).isZero();

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(PrivateKeyContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(KeySize.class);
        assertThat(value0.asString()).isEqualTo("2048");

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store_1 =
                getStoreOfValueType(SignatureAction.class, detectionStore.getChildren());
        assertThat(store_1).isNotNull();
        assertThat(store_1.getDetectionValues()).hasSize(1);
        assertThat(store_1.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
        IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
        assertThat(value0_1).isInstanceOf(SignatureAction.class);
        assertThat(value0_1.asString()).isEqualTo("SIGN");

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store_1_1 =
                getStoreOfValueType(ValueAction.class, store_1.getChildren());
        assertThat(store_1_1).isNotNull();
        assertThat(store_1_1.getDetectionValues()).hasSize(1);
        assertThat(store_1_1.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
        IValue<Tree> value0_1_1 = store_1_1.getDetectionValues().get(0);
        assertThat(value0_1_1).isInstanceOf(ValueAction.class);
        assertThat(value0_1_1.asString()).isEqualTo("RSA-PSS");

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store_1_1_1 =
                getStoreOfValueType(ValueAction.class, store_1_1.getChildren());
        assertThat(store_1_1_1).isNotNull();
        assertThat(store_1_1_1.getDetectionValues()).hasSize(1);
        assertThat(store_1_1_1.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
        IValue<Tree> value0_1_1_1 = store_1_1_1.getDetectionValues().get(0);
        assertThat(value0_1_1_1).isInstanceOf(ValueAction.class);
        assertThat(value0_1_1_1.asString()).isEqualTo("MGF1");

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store_1_1_1_1 =
                getStoreOfValueType(ValueAction.class, store_1_1_1.getChildren());
        assertThat(store_1_1_1_1).isNotNull();
        assertThat(store_1_1_1_1.getDetectionValues()).hasSize(1);
        assertThat(store_1_1_1_1.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        IValue<Tree> value0_1_1_1_1 = store_1_1_1_1.getDetectionValues().get(0);
        assertThat(value0_1_1_1_1).isInstanceOf(ValueAction.class);
        assertThat(value0_1_1_1_1.asString()).isEqualTo("SHA256");

        assertThat(nodes).hasSize(1);
    }

        @Override
        public void update(
                        @Nonnull com.ibm.engine.detection.Finding<PythonCheck, Tree, Symbol, PythonVisitorContext>
                                        finding) {
                capturedFindingCount++;
                capturedStore = finding.detectionStore();
                capturedNodes = pythonTranslationProcess.initiate(capturedStore);
                asserts(capturedFindingCount - 1, capturedStore, capturedNodes);
        }
}