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
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * The digests mirror the ciphers: the function name is the identity, and the fetch-by-name form has
 * to resolve through the same table or report nothing.
 *
 * <p>The three HMAC findings are the point of the second half. Each is an {@code HMAC} component
 * with no digest under it, and that is the intended answer rather than a gap: in every real wrapper
 * the {@code EVP_MD *} is a handle, and where it is written inline the digest is already a finding
 * of its own on the same line, so reading it here as well would report one digest twice.
 */
class OpenSslDigestTest extends TestBase {

    private final List<String> found = new ArrayList<>();

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/openssl/OpenSslDigestTestFile.cs", this);
        assertThat(found)
                .as("one component per digest-returning call, plus one per HMAC call")
                .containsExactly(
                        "SHA-256", // inline, as an argument of EVP_DigestInit_ex
                        "SHA-1",
                        "SHA-384",
                        "SHA3-256",
                        "SHAKE256",
                        "MD5",
                        "BLAKE2b",
                        "SM3",
                        "RIPEMD-160",
                        "SHA-512", // EVP_MD_fetch("SHA2-512")
                        "SHA-256", // EVP_get_digestbyname("SHA256")
                        "HMAC", // the one-shot form
                        "HMAC", // HMAC_Init_ex
                        "HMAC", // HMAC_Init
                        // EVP_MAC_fetch: the only OpenSSL call that names a MAC by string. Four
                        // further fetches in the fixture are asserted absent by this list being
                        // exact -- GMAC (mapper has it only as a cipher mode), BLAKE2BMAC (the
                        // mapper's BLAKE2b is a digest, not a MAC), an invented name, and a name
                        // taken from a parameter.
                        "HMAC",
                        "CMAC",
                        "KMAC128",
                        "KMAC256", // written "KMAC256", the hyphenless spelling
                        "Poly1305", // written "poly1305": the fetch is case-insensitive
                        "SipHash");
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
            case 0 -> assertChild(nodes.get(0), DigestSize.class, 256);
            case 3 -> assertChild(nodes.get(0), DigestSize.class, 256);
            // The digest of an HMAC is a handle this plugin cannot follow, so it must be absent.
            case 11, 12, 13 -> assertNoChild(nodes.get(0), MessageDigest.class);
            // EVP_MD_fetch with a name that is not a digest.
            case 14 -> assertThat(nodes).isEmpty();
            default -> {
                /* covered by containsExactly above */
            }
        }
    }
}
