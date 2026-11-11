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
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mode;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * An OpenSSL cipher is named by the function that returns it, so these assertions are about whether
 * one function name yields all three of algorithm, key length and mode.
 *
 * <p>The counter-checks are the half that matters. Every rule here matches on an {@code ANY}
 * receiver, so what keeps them quiet is that the method name must be in {@code OpenSslApi}'s table
 * and that a fetch name must resolve through it: a function OpenSSL does not have, an algorithm
 * string that is not a cipher, and a name built at run time all have to stay silent, and {@code
 * EVP_EncryptInit_ex} on a handle has to stay silent as well -- it names no algorithm, and a rule
 * there could only invent one.
 */
class OpenSslCipherTest extends TestBase {

    private final List<String> found = new ArrayList<>();

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/openssl/OpenSslCipherTestFile.cs", this);
        assertThat(found)
                .as("one component per cipher-returning call, and nothing else")
                .containsExactly(
                        "AES-256-GCM", // inline, as an argument of EVP_EncryptInit_ex
                        "AES-128-CBC", // the same, qualified with the P/Invoke holder
                        "ChaCha20-Poly1305", // held in a local first
                        "DESede168-CBC", // ede3 is three-key Triple DES
                        "DESede112-CBC", // ede is two-key
                        "RC4", // key length settable later, so none is claimed
                        "RC4-40", // the export variant names its own
                        "AES-192-CFB8", // the feedback width is in the name
                        "AES-256-WRAP", // key wrap
                        "DES-56-ECB", // the 56 bits are the mapper's, not the name's
                        "AES-256-GCM", // EVP_CIPHER_fetch("AES-256-GCM")
                        "DESede168-CBC"); // EVP_get_cipherbyname("DES-EDE3-CBC")
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        // A detection whose value the translator declines -- an algorithm string that is not a
        // cipher -- arrives with no nodes at all and contributes nothing.
        nodes.forEach(node -> found.add(node.asString()));
        switch (findingId) {
            case 0 -> {
                assertChild(nodes.get(0), KeyLength.class, 256);
                assertChild(nodes.get(0), Mode.class, "GCM");
            }
            // RC4's key length is set with EVP_CIPHER_CTX_set_key_length, not by the function, so
            // it must be absent rather than defaulted to 128.
            case 5 -> {
                assertNoChild(nodes.get(0), KeyLength.class);
                assertNoChild(nodes.get(0), Mode.class);
            }
            case 6 -> assertChild(nodes.get(0), KeyLength.class, 40);
            case 8 -> assertChild(nodes.get(0), Mode.class, "WRAP");
            // EVP_CIPHER_fetch with a string that is not a cipher name.
            case 12 -> assertThat(nodes).isEmpty();
            default -> {
                /* covered by containsExactly above */
            }
        }
    }
}
