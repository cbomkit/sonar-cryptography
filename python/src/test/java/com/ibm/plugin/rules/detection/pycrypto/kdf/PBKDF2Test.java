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
package com.ibm.plugin.rules.detection.pycrypto.kdf;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.IterationCount;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.NumberOfIterations;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.algorithms.PBKDF2;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

public class PBKDF2Test extends TestBase {

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/pycrypto/kdf/PBKDF2TestFile.py", this);
    }

    @Override
    @SuppressWarnings("unchecked")
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(findingId).isZero();

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext())
                .isInstanceOf(KeyDerivationFunctionContext.class);
        IValue<Tree> value = detectionStore.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(ValueAction.class);
        assertThat(value.asString()).isEqualTo("PBKDF2");

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> iterStore =
                getStoreOfValueType(IterationCount.class, detectionStore.getChildren());
        assertThat(iterStore).isNotNull();
        assertThat(iterStore.getDetectionValues().get(0).asString()).isEqualTo("1000");

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> keySizeStore =
                getStoreOfValueType(KeySize.class, detectionStore.getChildren());
        assertThat(keySizeStore).isNotNull();
        assertThat(keySizeStore.getDetectionValues().get(0).asString()).isEqualTo("512");

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> algorithmStore =
                getStoreOfValueType(Algorithm.class, detectionStore.getChildren());
        assertThat(algorithmStore).isNotNull();
        assertThat(algorithmStore.getDetectionValues().get(0).asString()).isEqualTo("SHA512");

        assertThat(nodes).hasSize(1);
        INode root = nodes.get(0);
        assertThat(root.getKind()).isEqualTo(PasswordBasedKeyDerivationFunction.class);
        assertThat(root).isInstanceOf(PBKDF2.class);
        assertThat(root.getChildren()).hasSize(4);
        assertThat(root.asString()).isEqualTo("PBKDF2-SHA-512");

        INode md = root.getChildren().get(MessageDigest.class);
        assertThat(md).isNotNull();
        assertThat(md.getChildren()).hasSize(4);
        assertThat(md.asString()).isEqualTo("SHA-512");
        assertThat(md.getChildren().get(DigestSize.class).asString()).isEqualTo("512");
        assertThat(md.getChildren().get(Oid.class).asString()).isEqualTo("2.16.840.1.101.3.4.2.3");
        assertThat(md.getChildren().get(Digest.class).asString()).isEqualTo("DIGEST");
        assertThat(md.getChildren().get(BlockSize.class).asString()).isEqualTo("1024");

        assertThat(root.getChildren().get(KeyLength.class).asString()).isEqualTo("512");
        assertThat(root.getChildren().get(KeyDerivation.class).asString())
                .isEqualTo("KEYDERIVATION");
        assertThat(root.getChildren().get(NumberOfIterations.class).asString()).isEqualTo("1000");
    }
}
