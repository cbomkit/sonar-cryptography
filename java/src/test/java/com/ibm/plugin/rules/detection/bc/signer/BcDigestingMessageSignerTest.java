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
package com.ibm.plugin.rules.detection.bc.signer;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.ExtendableOutputFunction;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.ParameterSetIdentifier;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.collections.MergeableCollection;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.plugin.TestBase;
import com.ibm.plugin.rules.detection.bc.BouncyCastleJars;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class BcDigestingMessageSignerTest extends TestBase {
    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/bc/signer/BcDigestingMessageSignerTestFile.java")
                .withChecks(this)
                .withClassPath(BouncyCastleJars.latestJar)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        if (findingId == 0) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(DigestContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("SHA256Digest");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // MessageDigest
            INode messageDigestNode = nodes.get(0);
            assertThat(messageDigestNode.getKind()).isEqualTo(MessageDigest.class);
            assertThat(messageDigestNode.getChildren()).hasSize(4);
            assertThat(messageDigestNode.asString()).isEqualTo("SHA-256");

            // Digest under MessageDigest
            INode digestNode = messageDigestNode.getChildren().get(Digest.class);
            assertThat(digestNode).isNotNull();
            assertThat(digestNode.getChildren()).isEmpty();
            assertThat(digestNode.asString()).isEqualTo("DIGEST");

            // BlockSize under MessageDigest
            INode blockSizeNode = messageDigestNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("512");

            // DigestSize under MessageDigest
            INode digestSizeNode = messageDigestNode.getChildren().get(DigestSize.class);
            assertThat(digestSizeNode).isNotNull();
            assertThat(digestSizeNode.getChildren()).isEmpty();
            assertThat(digestSizeNode.asString()).isEqualTo("256");

            // Oid under MessageDigest
            INode oidNode = messageDigestNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.2.1");
        } else if (findingId == 1) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(DigestContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("SHAKEDigest");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store1 =
                    getStoreOfValueType(
                            com.ibm.engine.model.DigestSize.class, detectionStore.getChildren());
            assertThat(store1).isNotNull();
            assertThat(store1.getDetectionValues()).hasSize(1);
            assertThat(store1.getDetectionValueContext()).isInstanceOf(DigestContext.class);
            IValue<Tree> value01 = store1.getDetectionValues().get(0);
            assertThat(value01).isInstanceOf(com.ibm.engine.model.DigestSize.class);
            assertThat(value01.asString()).isEqualTo("128");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // ExtendableOutputFunction
            INode extendableOutputFunctionNode = nodes.get(0);
            assertThat(extendableOutputFunctionNode.getKind())
                    .isEqualTo(ExtendableOutputFunction.class);
            assertThat(extendableOutputFunctionNode.getChildren()).hasSize(2);
            assertThat(extendableOutputFunctionNode.asString()).isEqualTo("SHAKE128");

            // Digest under ExtendableOutputFunction
            INode digestNode = extendableOutputFunctionNode.getChildren().get(Digest.class);
            assertThat(digestNode).isNotNull();
            assertThat(digestNode.getChildren()).isEmpty();
            assertThat(digestNode.asString()).isEqualTo("DIGEST");

            // DigestSize under ExtendableOutputFunction
            INode digestSizeNode = extendableOutputFunctionNode.getChildren().get(DigestSize.class);
            assertThat(digestSizeNode).isNotNull();
            assertThat(digestSizeNode.getChildren()).isEmpty();
            assertThat(digestSizeNode.asString()).isEqualTo("128");
        } else if (findingId == 2) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(DigestContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("SHAKEDigest");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store1 =
                    getStoreOfValueType(
                            com.ibm.engine.model.DigestSize.class, detectionStore.getChildren());
            assertThat(store1).isNotNull();
            assertThat(store1.getDetectionValues()).hasSize(1);
            assertThat(store1.getDetectionValueContext()).isInstanceOf(DigestContext.class);
            IValue<Tree> value01 = store1.getDetectionValues().get(0);
            assertThat(value01).isInstanceOf(com.ibm.engine.model.DigestSize.class);
            assertThat(value01.asString()).isEqualTo("256");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // ExtendableOutputFunction
            INode extendableOutputFunctionNode = nodes.get(0);
            assertThat(extendableOutputFunctionNode.getKind())
                    .isEqualTo(ExtendableOutputFunction.class);
            assertThat(extendableOutputFunctionNode.getChildren()).hasSize(2);
            assertThat(extendableOutputFunctionNode.asString()).isEqualTo("SHAKE256");

            // Digest under ExtendableOutputFunction
            INode digestNode = extendableOutputFunctionNode.getChildren().get(Digest.class);
            assertThat(digestNode).isNotNull();
            assertThat(digestNode.getChildren()).isEmpty();
            assertThat(digestNode.asString()).isEqualTo("DIGEST");

            // DigestSize under ExtendableOutputFunction
            INode digestSizeNode = extendableOutputFunctionNode.getChildren().get(DigestSize.class);
            assertThat(digestSizeNode).isNotNull();
            assertThat(digestSizeNode.getChildren()).isEmpty();
            assertThat(digestSizeNode.asString()).isEqualTo("256");
        } else if (findingId == 3) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(SignatureContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("DigestingMessageSigner");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store1 =
                    getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
            assertThat(store1).isNotNull();
            assertThat(store1.getDetectionValues()).hasSize(1);
            assertThat(store1.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
            IValue<Tree> value01 = store1.getDetectionValues().get(0);
            assertThat(value01).isInstanceOf(OperationMode.class);
            assertThat(value01.asString()).isEqualTo("1");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store2 =
                    getStoreOfValueType(ValueAction.class, detectionStore.getChildren());
            assertThat(store2).isNotNull();
            assertThat(store2.getDetectionValues()).hasSize(1);
            assertThat(store2.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
            IValue<Tree> value02 = store2.getDetectionValues().get(0);
            assertThat(value02).isInstanceOf(ValueAction.class);
            assertThat(value02.asString()).isEqualTo("SPHINCS256Signer");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store21 =
                    getStoreOfValueType(ValueAction.class, store2.getChildren());
            assertThat(store21).isNotNull();
            assertThat(store21.getDetectionValues()).hasSize(1);
            assertThat(store21.getDetectionValueContext()).isInstanceOf(DigestContext.class);
            IValue<Tree> value021 = store21.getDetectionValues().get(0);
            assertThat(value021).isInstanceOf(ValueAction.class);
            assertThat(value021.asString()).isEqualTo("SHAKEDigest");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store211 =
                    getStoreOfValueType(
                            com.ibm.engine.model.DigestSize.class, store21.getChildren());
            assertThat(store211).isNotNull();
            assertThat(store211.getDetectionValues()).hasSize(1);
            assertThat(store211.getDetectionValueContext()).isInstanceOf(DigestContext.class);
            IValue<Tree> value0211 = store211.getDetectionValues().get(0);
            assertThat(value0211).isInstanceOf(com.ibm.engine.model.DigestSize.class);
            assertThat(value0211.asString()).isEqualTo("128");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store22 =
                    getStoreOfValueType(ValueAction.class, store2.getChildren());
            assertThat(store22).isNotNull();
            assertThat(store22.getDetectionValues()).hasSize(1);
            assertThat(store22.getDetectionValueContext()).isInstanceOf(DigestContext.class);
            IValue<Tree> value022 = store22.getDetectionValues().get(0);
            assertThat(value022).isInstanceOf(ValueAction.class);
            assertThat(value022.asString()).isEqualTo("SHAKEDigest");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // Signature
            INode signatureNode = nodes.get(0);
            assertThat(signatureNode.getKind()).isEqualTo(Signature.class);
            assertThat(signatureNode.getChildren()).hasSize(4);
            assertThat(signatureNode.asString()).isEqualTo("SPHINCS-256");

            // Sign under Signature
            INode signNode = signatureNode.getChildren().get(Sign.class);
            assertThat(signNode).isNotNull();
            assertThat(signNode.getChildren()).isEmpty();
            assertThat(signNode.asString()).isEqualTo("SIGN");

            // MessageDigest under Signature
            INode messageDigestNode = signatureNode.getChildren().get(MessageDigest.class);
            assertThat(messageDigestNode).isNotNull();
            assertThat(messageDigestNode.getChildren()).hasSize(4);
            assertThat(messageDigestNode.asString()).isEqualTo("SHA-256");

            // Digest under MessageDigest under Signature
            INode digestNode = messageDigestNode.getChildren().get(Digest.class);
            assertThat(digestNode).isNotNull();
            assertThat(digestNode.getChildren()).isEmpty();
            assertThat(digestNode.asString()).isEqualTo("DIGEST");

            // BlockSize under MessageDigest under Signature
            INode blockSizeNode = messageDigestNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("512");

            // DigestSize under MessageDigest under Signature
            INode digestSizeNode = messageDigestNode.getChildren().get(DigestSize.class);
            assertThat(digestSizeNode).isNotNull();
            assertThat(digestSizeNode.getChildren()).isEmpty();
            assertThat(digestSizeNode.asString()).isEqualTo("256");

            // Oid under MessageDigest under Signature
            INode oidNode = messageDigestNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.2.1");

            // ParameterSetIdentifier under Signature
            INode parameterSetIdentifierNode =
                    signatureNode.getChildren().get(ParameterSetIdentifier.class);
            assertThat(parameterSetIdentifierNode).isNotNull();
            assertThat(parameterSetIdentifierNode.getChildren()).isEmpty();
            assertThat(parameterSetIdentifierNode.asString()).isEqualTo("256");

            // MergeableCollection under Signature
            INode mergeableCollectionNode =
                    signatureNode.getChildren().get(MergeableCollection.class);
            assertThat(mergeableCollectionNode).isNotNull();
            assertThat(mergeableCollectionNode.getChildren()).hasSize(1);
            assertThat(mergeableCollectionNode.asString()).isEqualTo("[SHAKE, SHAKE]");

            // DigestSize under MergeableCollection under Signature
            INode digestSizeNode1 = mergeableCollectionNode.getChildren().get(DigestSize.class);
            assertThat(digestSizeNode1).isNotNull();
            assertThat(digestSizeNode1.getChildren()).isEmpty();
            assertThat(digestSizeNode1.asString()).isEqualTo("128");
        }
    }
}
