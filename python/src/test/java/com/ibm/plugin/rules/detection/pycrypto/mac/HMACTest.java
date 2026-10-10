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
package com.ibm.plugin.rules.detection.pycrypto.mac;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.MacContext;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

public class HMACTest extends TestBase {

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/pycrypto/mac/HMACTestFile.py", this);
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
        assertThat(value).isInstanceOf(Algorithm.class);
        assertThat(value.asString()).isEqualTo("SHA256");

        assertThat(nodes).hasSize(1);
        INode mac = nodes.get(0);
        assertThat(mac).isInstanceOf(Mac.class);
        assertThat(mac.asString()).isEqualTo("HMAC-SHA-256");
        assertThat(mac.getChildren()).hasSize(3);

        INode digest = mac.getChildren().get(MessageDigest.class);
        assertThat(digest).isNotNull();
        assertThat(digest.asString()).isEqualTo("SHA-256");
        assertThat(digest.getChildren()).hasSize(4);

        assertThat(digest.getChildren().get(Digest.class)).isNotNull();
        assertThat(digest.getChildren().get(Digest.class).asString()).isEqualTo("DIGEST");
        assertThat(digest.getChildren().get(BlockSize.class)).isNotNull();
        assertThat(digest.getChildren().get(BlockSize.class).asString()).isEqualTo("512");
        assertThat(digest.getChildren().get(Oid.class)).isNotNull();
        assertThat(digest.getChildren().get(Oid.class).asString())
                .isEqualTo("2.16.840.1.101.3.4.2.1");
        assertThat(digest.getChildren().get(DigestSize.class)).isNotNull();
        assertThat(digest.getChildren().get(DigestSize.class).asString()).isEqualTo("256");

        assertThat(mac.getChildren().get(Oid.class)).isNotNull();
        assertThat(mac.getChildren().get(Oid.class).asString()).isEqualTo("1.2.840.113549.2.9");
    }
}
