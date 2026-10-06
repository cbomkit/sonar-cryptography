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
package com.ibm.mapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.Handler;
import com.ibm.engine.executive.IStatusReporting;
import com.ibm.engine.language.IScanContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.model.mode.ECB;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/** The node a translated detection store tree is rooted at. */
class ITranslatorTraverserTest {

    private final DetectionLocation location = mock(DetectionLocation.class);

    @SuppressWarnings("unchecked")
    private final IDetectionRule<Object> rule = mock(IDetectionRule.class);

    @SuppressWarnings("unchecked")
    private final IScanContext<Object, Object> scanContext = mock(IScanContext.class);

    @SuppressWarnings("unchecked")
    private final Handler<Object, Object, Object, Object> handler = mock(Handler.class);

    @SuppressWarnings("unchecked")
    private final IStatusReporting<Object, Object, Object, Object> statusReporting =
            mock(IStatusReporting.class);

    private final Map<DetectionStore<Object, Object, Object, Object>, INode> nodes =
            new IdentityHashMap<>();

    /** The parameter a store's node is the value of; -1 (the call itself) when absent. */
    private final Map<DetectionStore<Object, Object, Object, Object>, Integer> parameterIds =
            new IdentityHashMap<>();

    @Test
    void rootWithoutNodeIsDescribedByTheArgumentsOfItsCall() {
        // SSL_CTX_new(TLS_method()); SSL_CTX_set_ciphersuites(ctx, "...")
        final DetectionStore<Object, Object, Object, Object> context = store(null);
        context.attach(store(suites()));
        context.attach(0, store(new TLS(location)));

        final List<INode> roots = traverse(context);

        assertThat(roots).singleElement().isInstanceOf(TLS.class);
        assertThat(roots.get(0).hasChildOfType(CipherSuiteCollection.class)).isPresent();
    }

    @Test
    void rootWithNodeKeepsIt() {
        final TLS tls = new TLS(location);
        final DetectionStore<Object, Object, Object, Object> context = store(tls);
        context.attach(store(suites()));
        context.attach(0, store(new Version("1.2", location)));

        final List<INode> roots = traverse(context);

        assertThat(roots).containsExactly(tls);
        assertThat(tls.hasChildOfType(CipherSuiteCollection.class)).isPresent();
        assertThat(tls.hasChildOfType(Version.class)).isPresent();
    }

    @Test
    void anotherValueOfTheRootGivesAnotherRoot() {
        final AES cipher = new AES(location);
        final DetectionStore<Object, Object, Object, Object> selection = store(cipher);
        selection.attach(store(new KeyLength(128, location)));
        selection.attach(store(new KeyLength(256, location)));

        final List<INode> roots = traverse(selection);

        assertThat(roots).hasSize(2);
        assertThat(roots.get(0)).isSameAs(cipher);
        assertThat(roots.get(0).hasChildOfType(KeyLength.class).map(INode::asString))
                .contains("128");
        assertThat(roots.get(1).hasChildOfType(KeyLength.class).map(INode::asString))
                .contains("256");
    }

    @Test
    void anotherValueBelowTheRootGivesACopyOfTheWholeTree() {
        // AES_set_encrypt_key(k, 128, &key); AES_set_encrypt_key(k, 256, &key);
        // AES_ecb_encrypt(in, out, &key, AES_ENCRYPT)
        final AES operation = new AES(new ECB(location), location);
        final DetectionStore<Object, Object, Object, Object> encryption = store(operation);
        final DetectionStore<Object, Object, Object, Object> keySetup = store(new AES(location));
        encryption.attach(keySetup);
        keySetup.attach(store(new KeyLength(128, location)));
        keySetup.attach(store(new KeyLength(256, location)));

        final List<INode> roots = traverse(encryption);

        assertThat(roots).hasSize(2);
        assertThat(roots.get(0)).isSameAs(operation);
        assertThat(keyLengthOfKeySetup(roots.get(0))).isEqualTo("128");
        final INode alternative = roots.get(1);
        assertThat(alternative).isInstanceOf(AES.class).isNotSameAs(operation);
        assertThat(alternative.hasChildOfType(Mode.class))
                .get()
                .isInstanceOf(ECB.class)
                .isNotSameAs(operation.getChildren().get(Mode.class));
        assertThat(keyLengthOfKeySetup(alternative)).isEqualTo("256");
    }

    @Test
    void anotherValueOfTheRootGivesATreeWithWhatIsFoundAfterIt() {
        final AES cipher = new AES(location);
        final DetectionStore<Object, Object, Object, Object> selection = store(cipher);
        selection.attach(store(new KeyLength(128, location)));
        selection.attach(store(new KeyLength(256, location)));
        selection.attach(store(new ECB(location)));

        final List<INode> roots = traverse(selection);

        assertThat(roots).hasSize(2);
        assertThat(roots)
                .allSatisfy(root -> assertThat(root.hasChildOfType(Mode.class)).isPresent());
        assertThat(roots.get(1).hasChildOfType(KeyLength.class).map(INode::asString))
                .contains("256");
    }

    @Test
    void anotherValueKeepsWhatIsFoundBelowIt() {
        final AES cipher = new AES(location);
        final DetectionStore<Object, Object, Object, Object> selection = store(cipher);
        selection.attach(store(new KeyLength(128, location)));
        final DetectionStore<Object, Object, Object, Object> other =
                store(new KeyLength(256, location));
        selection.attach(other);
        other.attach(store(new Oid("1.2.3", location)));

        final List<INode> roots = traverse(selection);

        assertThat(roots).hasSize(2);
        assertThat(roots.get(1).hasChildOfType(KeyLength.class))
                .get()
                .satisfies(keyLength -> assertThat(keyLength.asString()).isEqualTo("256"))
                .satisfies(
                        keyLength -> assertThat(keyLength.hasChildOfType(Oid.class)).isPresent());
    }

    @Test
    void aCallBringingAnotherAlgorithmToAnObjectCreatedWithoutArgumentsIsAnotherUse() {
        // ctx = EVP_CIPHER_CTX_new(); EVP_EncryptInit_ex(ctx, cipher, ...);
        // EVP_DecryptInit_ex(ctx, other_cipher, ...); EVP_CIPHER_CTX_set_key_length(ctx, 32)
        final DetectionStore<Object, Object, Object, Object> context = store(null);
        final AES first = new AES(new ECB(location), location);
        final AES second = new AES(location);
        context.attach(store(first));
        context.attach(store(second));
        context.attach(store(new KeyLength(256, location)));

        final List<INode> roots = traverse(context);

        assertThat(roots).containsExactly(first, second);
        assertThat(first.hasChildOfType(KeyLength.class)).isEmpty();
        assertThat(second.hasChildOfType(KeyLength.class).map(INode::asString)).contains("256");
    }

    @Test
    void anObjectDescribedByTheArgumentsOfItsCreationHasOneUse() {
        // ctx = EVP_MAC_CTX_new(mac); EVP_MAC_init(ctx, key, len, params with a cipher)
        final DetectionStore<Object, Object, Object, Object> context = store(null);
        final AES created = new AES(location);
        context.attach(0, store(created));
        context.attach(store(new AES(new ECB(location), location)));

        final List<INode> roots = traverse(context);

        assertThat(roots).containsExactly(created);
    }

    @Test
    void anArgumentWithoutNodeConfiguresTheOperatedObjectWhereTheTranslatorSaysSo() {
        // kdf = EVP_KDF_fetch(...); EVP_KDF_derive(ctx, out, 32, params with a mode)
        final AES operated = new AES(location);
        final DetectionStore<Object, Object, Object, Object> fetch = store(operated);
        final KeyLength keyLength = new KeyLength(256, location);
        final DetectionStore<Object, Object, Object, Object> derive = parameterStore(2, keyLength);
        fetch.attach(derive);
        derive.attach(3, store(new ECB(location)));

        traverse(fetch, true);

        assertThat(operated.hasChildOfType(Mode.class)).isPresent();
        assertThat(keyLength.hasChildOfType(Mode.class)).isEmpty();
    }

    @Test
    void anArgumentWithoutNodeAddsToTheFirstNodeOfTheCallByDefault() {
        final AES operated = new AES(location);
        final DetectionStore<Object, Object, Object, Object> fetch = store(operated);
        final KeyLength keyLength = new KeyLength(256, location);
        final DetectionStore<Object, Object, Object, Object> derive = parameterStore(2, keyLength);
        fetch.attach(derive);
        derive.attach(3, store(new ECB(location)));

        traverse(fetch, false);

        assertThat(keyLength.hasChildOfType(Mode.class)).isPresent();
    }

    @Test
    void aValueFoundAgainAddsWhatIsFoundBelowItToTheFirst() {
        // EVP_DigestSignInit(mdctx, &pctx, md, NULL, key);
        // EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
        // EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32)
        final AES operation = new AES(location);
        final DetectionStore<Object, Object, Object, Object> signing = store(operation);
        final AES first = new AES(location);
        signing.attach(store(first));
        final DetectionStore<Object, Object, Object, Object> again = store(new AES(location));
        signing.attach(again);
        again.attach(store(new KeyLength(256, location)));

        final List<INode> roots = traverse(signing);

        assertThat(roots).containsExactly(operation);
        assertThat(operation.hasChildOfType(BlockCipher.class)).containsSame(first);
        assertThat(first.hasChildOfType(KeyLength.class).map(INode::asString)).contains("256");
    }

    @Nonnull
    private static String keyLengthOfKeySetup(@Nonnull INode operation) {
        return operation
                .hasChildOfType(BlockCipher.class)
                .flatMap(keySetup -> keySetup.hasChildOfType(KeyLength.class))
                .map(INode::asString)
                .orElse("none");
    }

    @Nonnull
    private List<INode> traverse(@Nonnull DetectionStore<Object, Object, Object, Object> root) {
        return traverse(root, false);
    }

    @Nonnull
    private List<INode> traverse(
            @Nonnull DetectionStore<Object, Object, Object, Object> root,
            boolean argumentsConfigureTheOperatedObject) {
        return new ITranslator.Traverser<>(
                        root,
                        store -> {
                            final Map<Integer, List<INode>> translated = new HashMap<>();
                            final INode node = nodes.get(store);
                            if (node != null) {
                                translated.put(
                                        parameterIds.getOrDefault(store, -1),
                                        new ArrayList<>(List.of(node)));
                            }
                            return translated;
                        },
                        argumentsConfigureTheOperatedObject)
                .translate();
    }

    @Nonnull
    private DetectionStore<Object, Object, Object, Object> parameterStore(
            int parameterId, @Nonnull INode node) {
        final DetectionStore<Object, Object, Object, Object> store = store(node);
        parameterIds.put(store, parameterId);
        return store;
    }

    @Nonnull
    private DetectionStore<Object, Object, Object, Object> store(INode node) {
        final DetectionStore<Object, Object, Object, Object> store =
                new DetectionStore<>(0, rule, scanContext, handler, statusReporting);
        if (node != null) {
            nodes.put(store, node);
        }
        return store;
    }

    @Nonnull
    private CipherSuiteCollection suites() {
        return new CipherSuiteCollection(
                List.of(new CipherSuite("TLS_AES_128_GCM_SHA256", location)));
    }
}
