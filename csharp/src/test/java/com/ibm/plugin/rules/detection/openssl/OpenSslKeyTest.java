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
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.NumberOfIterations;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.SaltLength;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Key generation, RSA padding and password-based derivation, where the detail is in the arguments
 * rather than in the function name alone.
 *
 * <p>Three kinds of assertion carry the weight here. The key sizes and curves prove that the value
 * beside the algorithm is read -- {@code RSA-4096}, {@code EC-prime256v1} from a numeric NID,
 * {@code EC-secp384r1} from a NID member name, {@code EC-secp521r1} from a group-name string. The
 * paddings prove that all six {@code RSA_*_PADDING} constants resolve, including {@code
 * RSA_NO_PADDING}, which is recorded rather than dropped because raw RSA is a finding. And the
 * PBKDF2 assertions prove the three numbers an auditor reads such a call site for: 600000
 * iterations, a 16-byte salt and a 32-byte derived key, reported in bits.
 *
 * <p>The counter-checks assert absence of a size that arrives in a parameter, of an iteration count
 * that does, of a NID that is not a curve, of a group name that is not one, and of a padding
 * constant that is not one -- and that {@code EVP_PKEY_keygen}, which names neither algorithm nor
 * size, produces nothing at all.
 */
class OpenSslKeyTest extends TestBase {

    private final List<String> found = new ArrayList<>();

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/openssl/OpenSslKeyTestFile.cs", this);
        assertThat(found)
                .as("one component per key-generation, padding or derivation call")
                .containsExactly(
                        "RSA-4096", // RSA_generate_key_ex
                        "RSA-1024", // the same, at a size worth flagging
                        "RSA-2048", // RSA_generate_key, size at index 0
                        "RSA-3072", // RSA_generate_multi_prime_key
                        "RSA-2048", // EVP_RSA_gen
                        "RSA-3072", // EVP_PKEY_CTX_set_rsa_keygen_bits
                        "DSA-2048",
                        "FFDH-2048", // EVP_PKEY_CTX_set_dh_paramgen_prime_len
                        "EC-prime256v1", // NID by numeric value
                        "EC-secp384r1", // NID by member name
                        "EC-secp521r1", // group name "P-521"
                        "RSA-4096", // EVP_PKEY_Q_keygen(.., "RSA", 4096)
                        "EC", // EVP_PKEY_Q_keygen(.., "EC", "P-384"); curve is a child
                        "Ed25519", // a parameterless type
                        "ML-DSA-65",
                        "RSA-OAEP", // set_rsa_padding(RSA_PKCS1_OAEP_PADDING)
                        "RSA", // set_rsa_padding(RSA_PKCS1_PADDING)
                        "RSA", // set_rsa_padding(RSA_NO_PADDING)
                        "RSA", // set_rsa_padding(RSA_PKCS1_PSS_PADDING)
                        "RSA", // set_rsa_padding(RSA_X931_PADDING)
                        "RSA-OAEP", // RSA_public_encrypt
                        "RSA-OAEP", // RSA_private_decrypt
                        "RSA", // RSA_private_encrypt
                        "RSA", // RSA_public_decrypt
                        "SHA-256", // the EVP_sha256() written inside the PBKDF2 call
                        "PBKDF2",
                        "PBKDF2-SHA-1", // the name states the pseudo-random function
                        "scrypt",
                        "scrypt", // EVP_PBE_scrypt_ex
                        "HKDF", // EVP_KDF_fetch("HKDF")
                        "PBKDF2", // EVP_KDF_fetch("PBKDF2")
                        "RSA", // counter-check: size in a parameter
                        "SHA-256", // the digest of the next call, which is still inline
                        "PBKDF2", // counter-check: iteration count in a parameter
                        "RSA"); // counter-check: a padding constant that is not one
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
            case 0 -> assertChild(nodes.get(0), KeyLength.class, 4096);
            case 8 -> assertChild(nodes.get(0), EllipticCurve.class, "prime256v1");
            case 11 -> assertChild(nodes.get(0), KeyLength.class, 4096);
            // The EC shorthand: the type string is the component and the curve is its child, so
            // the curve has to be there although the component's name does not spell it.
            case 12 -> {
                assertChild(nodes.get(0), EllipticCurve.class, "secp384r1");
                assertNoChild(nodes.get(0), KeyLength.class);
            }
            case 17 -> assertChild(nodes.get(0), Padding.class, "NONE");
            case 18 -> assertChild(nodes.get(0), Padding.class, "PSS");
            case 19 -> assertChild(nodes.get(0), Padding.class, "X9.31");
            // PBKDF2: 600000 iterations, a 16-byte salt and a 32-byte key, in bits.
            case 25 -> {
                assertChild(nodes.get(0), NumberOfIterations.class, 600000);
                assertChild(nodes.get(0), SaltLength.class, 128);
                assertChild(nodes.get(0), KeyLength.class, 256);
            }
            case 26 -> {
                assertChild(nodes.get(0), NumberOfIterations.class, 1000);
                assertChild(nodes.get(0), SaltLength.class, 64);
                assertChild(nodes.get(0), KeyLength.class, 160);
            }
            // scrypt: the lengths are read; N, r and p have no model and are not invented.
            case 27, 28 -> {
                assertChild(nodes.get(0), SaltLength.class, 256);
                assertChild(nodes.get(0), KeyLength.class, 512);
                assertNoChild(nodes.get(0), NumberOfIterations.class);
            }
            // The key size arrives in a method parameter.
            case 31 -> assertNoChild(nodes.get(0), KeyLength.class);
            // The iteration count arrives in a method parameter; the two literal lengths stay.
            case 33 -> {
                assertNoChild(nodes.get(0), NumberOfIterations.class);
                assertChild(nodes.get(0), SaltLength.class, 128);
            }
            // A NID that is not a curve, and a group name that is not one: no component at all,
            // because the curve was the whole finding.
            case 34, 35, 37 -> assertThat(nodes).isEmpty();
            // A padding constant that is not one: the RSA context is still stated, the padding is
            // not guessed.
            case 36 -> assertNoChild(nodes.get(0), Padding.class);
            default -> {
                /* covered by containsExactly above */
            }
        }
    }
}
