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
package com.ibm.plugin.rules.detection.openssl.digest;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class OpenSSLNameCanonicalizerFactoryTest {

    /**
     * Every canonicalized digest name must be a string {@link
     * com.ibm.plugin.translation.translator.contexts.CxxDigestContextTranslator} actually
     * recognizes, otherwise the finding is silently dropped as {@code Optional.empty()}.
     */
    @ParameterizedTest
    @CsvSource({
        // OpenSSL EVP_MD name, expected canonical form
        "SHAKE128, SHAKE128",
        "SHAKE256, SHAKE256",
        "RIPEMD160, RIPEMD160",
        "RMD160, RIPEMD160",
        "BLAKE2B512, BLAKE2B-512",
        "BLAKE2S256, BLAKE2S-256",
        "MDC2, MDC2",
        "SSL3-SHA1, SHA-1",
        "SSL3-MD5, MD5",
    })
    void canonicalizesOpenSslDigestNames(String openSslName, String expectedCanonical) {
        assertThat(
                        OpenSSLNameCanonicalizerFactory.canonicalize(
                                OpenSSLNameCanonicalizerFactory.DIGEST_NAMES, openSslName))
                .isEqualTo(expectedCanonical);
    }

    @Test
    void isCaseInsensitiveAndTrimsWhitespace() {
        assertThat(
                        OpenSSLNameCanonicalizerFactory.canonicalize(
                                OpenSSLNameCanonicalizerFactory.DIGEST_NAMES, " blake2b512 "))
                .isEqualTo("BLAKE2B-512");
    }

    /**
     * Every canonicalized group name must be a string {@link
     * com.ibm.plugin.translation.translator.contexts.CxxKeyContextTranslator} actually recognizes,
     * otherwise the finding is silently dropped as {@code Optional.empty()}.
     */
    @ParameterizedTest
    @CsvSource({
        // OpenSSL EVP_PKEY_CTX_set_group_name name, expected canonical form
        "P-192, EC-P192",
        "PRIME192V1, EC-P192",
        "P-224, EC-P224",
        "SECP224R1, EC-P224",
        "P-256, EC-P256",
        "PRIME256V1, EC-P256",
        "SECP256R1, EC-P256",
        "P-384, EC-P384",
        "SECP384R1, EC-P384",
        "P-521, EC-P521",
        "SECP521R1, EC-P521",
        "SECP256K1, EC-SECP256K1",
        "BRAINPOOLP256R1, EC-BRAINPOOLP256R1",
        "BRAINPOOLP384R1, EC-BRAINPOOLP384R1",
        "BRAINPOOLP512R1, EC-BRAINPOOLP512R1",
    })
    void canonicalizesOpenSslGroupNames(String openSslName, String expectedCanonical) {
        assertThat(
                        OpenSSLNameCanonicalizerFactory.canonicalize(
                                OpenSSLNameCanonicalizerFactory.GROUP_NAMES, openSslName))
                .isEqualTo(expectedCanonical);
    }

    @Test
    void unrecognizedNamePassesThroughUnchanged() {
        assertThat(OpenSSLNameCanonicalizerFactory.canonicalize(Map.of(), "SOME-UNKNOWN-DIGEST"))
                .isEqualTo("SOME-UNKNOWN-DIGEST");
    }
}
