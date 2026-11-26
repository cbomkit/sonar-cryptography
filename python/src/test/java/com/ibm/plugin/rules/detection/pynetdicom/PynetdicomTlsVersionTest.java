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
package com.ibm.plugin.rules.detection.pynetdicom;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Version;
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

class PynetdicomTlsVersionTest extends TestBase {

    /** The TLS node expected for each finding, in the order of the test file. */
    private static final List<String> EXPECTED =
            List.of(
                    "TLSv1.2", "TLSv1.1", "TLSv1.3", "TLSv1.2", "TLSv1.2", "TLSv1.0", "TLS", "TLS",
                    "TLS", "TLS", "TLS", "TLSv1.2");

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/pynetdicom/PynetdicomTlsVersionTestFile.py", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /*
         * Detection Store
         */
        assertThat(detectionStore.getChildren()).hasSize(1);

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);
        INode protocolNode = nodes.get(0);
        assertThat(protocolNode.asString()).isEqualTo("DICOM");
        INode tlsNode = protocolNode.getChildren().get(TLS.class);
        assertThat(tlsNode).isNotNull();
        final String expected = EXPECTED.get(findingId);
        assertThat(tlsNode.asString()).as("finding %d", findingId).isEqualTo(expected);
        INode versionNode = tlsNode.getChildren().get(Version.class);
        if ("TLS".equals(expected)) {
            assertThat(versionNode).isNull();
        } else {
            assertThat(versionNode).isNotNull();
            assertThat(versionNode.asString()).isEqualTo(expected.substring("TLSv".length()));
        }
    }
}
