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
package com.ibm.plugin.rules.detection.pycrypto.mac;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.MacContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.NodeOrigin;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

/** HMAC.new without digestmod: PyCryptodome defaults to MD5 (deprecated since 4.0). */
class HMACDefaultDigestTest extends TestBase {

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/pycrypto/mac/HMACDefaultDigestTestFile.py", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(findingId).isZero();

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(MacContext.class);
        assertThat(detectionStore.getChildren()).isEmpty();
        IValue<Tree> value = detectionStore.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(ValueAction.class);
        assertThat(value.asString()).isEqualTo("HMAC");

        assertThat(nodes).hasSize(1);
        INode mac = nodes.get(0);
        assertThat(mac.getKind()).isEqualTo(Mac.class);
        assertThat(mac.asString()).isEqualTo("HMAC-MD5");

        INode digest = mac.getChildren().get(MessageDigest.class);
        assertThat(digest).isNotNull();
        assertThat(digest.asString()).isEqualTo("MD5");
        assertThat(digest.getOrigin()).isEqualTo(NodeOrigin.DEFAULT);
    }
}
