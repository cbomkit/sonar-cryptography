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
package com.ibm.plugin.rules.detection.pynetdicom;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.Protocol;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

class PynetdicomAssociateTest extends TestBase {

    /** Whether the finding at this position carries TLS, in the order of the test file. */
    private static final List<Boolean> EXPECT_TLS =
            List.of(true, true, true, false, false, false, false);

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/pynetdicom/PynetdicomAssociateTestFile.py", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        final boolean tls = EXPECT_TLS.get(findingId);

        /*
         * Detection Store
         */
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(ProtocolContext.class);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);
        assertThat(value0.asString()).isEqualTo("DICOM");

        if (tls) {
            assertThat(detectionStore.getChildren()).hasSize(1);
            DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> child =
                    detectionStore.getChildren().get(0);
            assertThat(child.getDetectionValues()).hasSize(1);
            IValue<Tree> childValue = child.getDetectionValues().get(0);
            assertThat(childValue).isInstanceOf(Protocol.class);
            assertThat(childValue.asString()).isEqualTo("TLS");
        } else {
            assertThat(detectionStore.getChildren()).isEmpty();
        }

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);
        INode protocolNode = nodes.get(0);
        assertThat(protocolNode.getKind()).isEqualTo(com.ibm.mapper.model.Protocol.class);
        assertThat(protocolNode.asString()).isEqualTo("DICOM");
        if (tls) {
            assertThat(protocolNode.getChildren()).hasSize(1);
            INode tlsNode = protocolNode.getChildren().get(TLS.class);
            assertThat(tlsNode).isNotNull();
            assertThat(tlsNode.asString()).isEqualTo("TLS");
        } else {
            assertThat(protocolNode.getChildren()).isEmpty();
        }
    }
}
