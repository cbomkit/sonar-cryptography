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
package com.ibm.plugin.rules.detection.openssl;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpSymbol;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Which TLS version, and which suites, an OpenSSL endpoint written in C# offers.
 *
 * <p>Both spellings of the version constants are exercised: a C# {@code const int} initialised to
 * the hex wire value, which resolves to the number, and a member of a holder class, which resolves
 * to the name. The counter-checks cover the three ways the answer must stay absent -- {@code 0}
 * meaning "whatever the build supports", a version arriving in a method parameter, and a constant
 * that is not one of OpenSSL's -- and the three ways a cipher string is not a list of suites: a
 * list expression, an alias, and a string built at run time.
 *
 * <p>{@code SSL_CTX_set_options} appears once, and the assertion on it is that it reports a TLS
 * endpoint and <em>no</em> version although the call names three. {@code SSL_OP_NO_TLSv1} means TLS
 * 1.0 is refused; reporting it as offered would be the one mistake this rule set cannot make.
 */
class OpenSslTlsTest extends TestBase {

    private final List<String> found = new ArrayList<>();

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/openssl/OpenSslTlsTestFile.cs", this);
        assertThat(found)
                .as("the version where the call states one, a bare TLS where it does not")
                .containsExactly(
                        // SSL_CTX_new(TLS_client_method()): the method states no version, and the
                        // context call states that TLS is spoken. Two findings on one line.
                        "TLS",
                        "TLS",
                        "TLSv1.2", // TLSv1_2_method
                        "TLS",
                        "TLSv1.1", // TLSv1_1_method
                        "TLS",
                        "SSLv3", // SSLv3_method -- not TLS, and reported as what it is
                        "TLS",
                        "DTLS", // DTLS_method, version-flexible
                        "TLS",
                        "DTLSv1.2", // DTLSv1_2_method
                        "TLS",
                        // set_min_proto_version with each constant, as a C# const in hex
                        "TLSv1.0",
                        "TLSv1.1",
                        "TLSv1.2",
                        "TLSv1.3",
                        "SSLv3",
                        "DTLSv1.2",
                        // the same constants written as members of a holder class
                        "TLSv1.3", // set_max_proto_version
                        "TLSv1.2", // SSL_set_min_proto_version
                        "TLS", // set_cipher_list, one suite
                        "TLS", // set_cipher_list, two suites
                        "TLS", // set_ciphersuites, two TLS 1.3 suites
                        "TLS", // set_cipher_list, a 3DES suite
                        "TLS"); // set_options -- a TLS context, and no version
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        nodes.forEach(node -> found.add(node.asString()));
        switch (findingId) {
            // The version-flexible method and the context call both state TLS and no version.
            case 0, 1 -> assertNoChild(nodes.get(0), Version.class);
            case 14 -> assertChild(nodes.get(0), Version.class, "1.2");
            case 20 ->
                    assertChild(
                            nodes.get(0),
                            CipherSuiteCollection.class,
                            "[TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384]");
            case 21 ->
                    assertChild(
                            nodes.get(0),
                            CipherSuiteCollection.class,
                            "[TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,"
                                    + " TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384]");
            case 22 ->
                    assertChild(
                            nodes.get(0),
                            CipherSuiteCollection.class,
                            "[TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256]");
            case 23 ->
                    assertChild(
                            nodes.get(0),
                            CipherSuiteCollection.class,
                            "[TLS_RSA_WITH_3DES_EDE_CBC_SHA]");
            // set_options: a TLS endpoint, with neither a version nor a suite read out of the
            // SSL_OP_NO_* bitmask.
            case 24 -> {
                assertNoChild(nodes.get(0), Version.class);
                assertNoChild(nodes.get(0), CipherSuiteCollection.class);
            }
            // The four declined detections: version 0, an unknown version constant, a cipher-list
            // expression and a cipher-list alias.
            case 25, 26, 27, 28 -> assertThat(nodes).isEmpty();
            default -> {
                /* covered by containsExactly above */
            }
        }
    }
}
