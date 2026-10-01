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
package com.ibm.plugin.rules.detection.pycrypto.signature;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

public class DSSSignTest extends TestBase {

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/pycrypto/signature/DSSSignTestFile.py", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        if (findingId == 2) {
            // detection store
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(SignatureContext.class);
            IValue<Tree> value = detectionStore.getDetectionValues().get(0);
            assertThat(value).isInstanceOf(ValueAction.class);
            assertThat(value.asString()).isEqualTo("DSS");

            DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> sigStore =
                    getStoreOfValueType(SignatureAction.class, detectionStore.getChildren());
            assertThat(sigStore).isNotNull();
            assertThat(sigStore.getDetectionValues()).hasSize(1);
            assertThat(sigStore.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
            IValue<Tree> sigValue = sigStore.getDetectionValues().get(0);
            assertThat(sigValue).isInstanceOf(SignatureAction.class);
            assertThat(sigValue.asString()).isEqualTo("SIGN");

            // translation
            assertThat(nodes).hasSize(1);
            INode sig = nodes.get(0);
            assertThat(sig.getKind()).isEqualTo(Signature.class);
            assertThat(sig.getChildren()).hasSize(4);
            assertThat(sig.asString()).isEqualTo("DSA-SHA-256");

            INode oid = sig.getChildren().get(Oid.class);
            assertThat(oid).isNotNull();
            assertThat(oid.getChildren()).isEmpty();
            assertThat(oid.asString()).isEqualTo("2.16.840.1.101.3.4.3.2");

            INode key = sig.getChildren().get(Key.class);
            assertThat(key).isNotNull();
            assertThat(key.asString()).isEqualTo("DSA");
            assertThat(key.getChildren()).hasSize(2);
            INode keyGen = key.getChildren().get(KeyGeneration.class);
            assertThat(keyGen).isNotNull();
            assertThat(keyGen.getChildren()).isEmpty();
            assertThat(keyGen.asString()).isEqualTo("KEYGENERATION");

            INode md = sig.getChildren().get(MessageDigest.class);
            assertThat(md).isNotNull();
            assertThat(md.asString()).isEqualTo("SHA-256");
            assertThat(md.getChildren()).hasSize(4);
            INode mdOid = md.getChildren().get(Oid.class);
            assertThat(mdOid).isNotNull();
            assertThat(mdOid.getChildren()).isEmpty();
            assertThat(mdOid.asString()).isEqualTo("2.16.840.1.101.3.4.2.1");
            INode digestSize = md.getChildren().get(DigestSize.class);
            assertThat(digestSize).isNotNull();
            assertThat(digestSize.getChildren()).isEmpty();
            assertThat(digestSize.asString()).isEqualTo("256");
            INode blockSize = md.getChildren().get(BlockSize.class);
            assertThat(blockSize).isNotNull();
            assertThat(blockSize.getChildren()).isEmpty();
            assertThat(blockSize.asString()).isEqualTo("512");
            INode digest = md.getChildren().get(Digest.class);
            assertThat(digest).isNotNull();
            assertThat(digest.getChildren()).isEmpty();
            assertThat(digest.asString()).isEqualTo("DIGEST");

            INode sign = sig.getChildren().get(Sign.class);
            assertThat(sign).isNotNull();
            assertThat(sign.getChildren()).isEmpty();
            assertThat(sign.asString()).isEqualTo("SIGN");
        }
    }
}
