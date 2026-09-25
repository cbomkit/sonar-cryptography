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
package com.ibm.plugin.translation.translator.contexts;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.MacContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.CMAC;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.KMAC;
import com.ibm.mapper.model.algorithms.Poly1305;
import com.ibm.mapper.model.algorithms.SipHash;
import com.ibm.mapper.model.algorithms.blake.BLAKE2b;
import com.ibm.mapper.model.algorithms.blake.BLAKE2s;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class CxxMacContextTranslatorTest {

    private static final DetectionLocation TEST_LOCATION =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");

    private final CxxMacContextTranslator translator = new CxxMacContextTranslator();

    private Optional<INode> translate(String value) {
        return translator.translate(
                () -> "OpenSSL",
                new ValueAction<>(value, (AstNode) null),
                new MacContext(),
                TEST_LOCATION);
    }

    private static Stream<Arguments> hmacVariants() {
        return Stream.of(
                Arguments.of("HMAC-MD5", "HMAC-MD5"),
                Arguments.of("HMAC-SHA1", "HMAC-SHA-1"),
                Arguments.of("HMAC-SHA224", "HMAC-SHA-224"),
                Arguments.of("HMAC-SHA256", "HMAC-SHA-256"),
                Arguments.of("HMAC-SHA384", "HMAC-SHA-384"),
                Arguments.of("HMAC-SHA512", "HMAC-SHA-512"),
                Arguments.of("HMAC-SHA512/224", "HMAC-SHA-224"),
                Arguments.of("HMAC-SHA512/256", "HMAC-SHA-256"),
                Arguments.of("HMAC-SHA3-224", "HMAC-SHA3-224"),
                Arguments.of("HMAC-SHA3-256", "HMAC-SHA3-256"),
                Arguments.of("HMAC-SHA3-384", "HMAC-SHA3-384"),
                Arguments.of("HMAC-SHA3-512", "HMAC-SHA3-512"),
                Arguments.of("HMAC-RIPEMD160", "HMAC-RIPEMD"),
                Arguments.of("HMAC-SM3", "HMAC-SM3"));
    }

    @ParameterizedTest
    @MethodSource("hmacVariants")
    void hmacVariantsResolveToHmacOfTheExpectedDigest(String value, String expectedName) {
        Optional<INode> node = translate(value);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(HMAC.class);
        assertThat(node.get().asString()).isEqualTo(expectedName);
    }

    @Test
    void hmacBlake2bResolvesToHmac() {
        Optional<INode> node = translate("HMAC-BLAKE2B");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(HMAC.class);
        assertThat(node.get().asString()).isEqualTo("HMAC-BLAKE2b");
    }

    @Test
    void hmacBlake2sResolvesToHmac() {
        Optional<INode> node = translate("HMAC-BLAKE2S");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(HMAC.class);
        assertThat(node.get().asString()).isEqualTo("HMAC-BLAKE2s");
    }

    private static Stream<Arguments> cmacVariants() {
        return Stream.of(
                Arguments.of("CMAC-AES-128", "CMAC-AES"),
                Arguments.of("CMAC-AES-192", "CMAC-AES"),
                Arguments.of("CMAC-AES-256", "CMAC-AES"),
                Arguments.of("CMAC-3DES", "CMAC-DESede"),
                Arguments.of("CMAC-CAMELLIA-128", "CMAC-CAMELLIA"),
                Arguments.of("CMAC-CAMELLIA-192", "CMAC-CAMELLIA"),
                Arguments.of("CMAC-CAMELLIA-256", "CMAC-CAMELLIA"),
                Arguments.of("CMAC-ARIA-128", "CMAC-ARIA"),
                Arguments.of("CMAC-ARIA-192", "CMAC-ARIA"),
                Arguments.of("CMAC-ARIA-256", "CMAC-ARIA"),
                Arguments.of("CMAC-SM4", "CMAC-SM4"));
    }

    @ParameterizedTest
    @MethodSource("cmacVariants")
    void cmacVariantsResolveToCmacOfTheExpectedCipher(String value, String expectedName) {
        Optional<INode> node = translate(value);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(CMAC.class);
        assertThat(node.get().asString()).isEqualTo(expectedName);
    }

    @Test
    void gmacAes128WrapsAesInsideAGmacAlgorithm() {
        Optional<INode> node = translate("GMAC-AES-128");
        assertThat(node).isPresent();
        assertThat(node.get().asString()).isEqualTo("GMAC");
    }

    @Test
    void gmacAes192WrapsAesInsideAGmacAlgorithm() {
        Optional<INode> node = translate("GMAC-AES-192");
        assertThat(node).isPresent();
        assertThat(node.get().asString()).isEqualTo("GMAC");
    }

    @Test
    void gmacAes256WrapsAesInsideAGmacAlgorithm() {
        Optional<INode> node = translate("GMAC-AES-256");
        assertThat(node).isPresent();
        assertThat(node.get().asString()).isEqualTo("GMAC");
    }

    @Test
    void poly1305IsMapped() {
        Optional<INode> node = translate("POLY1305");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(Poly1305.class);
    }

    @Test
    void siphash24IsMappedToSipHash() {
        Optional<INode> node = translate("SIPHASH-2-4");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(SipHash.class);
    }

    @Test
    void siphash48IsMappedToSipHash() {
        Optional<INode> node = translate("SIPHASH-4-8");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(SipHash.class);
    }

    @Test
    void kmac128IsMapped() {
        Optional<INode> node = translate("KMAC128");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(KMAC.class);
        assertThat(node.get().asString()).isEqualTo("KMAC128");
    }

    @Test
    void kmac256IsMapped() {
        Optional<INode> node = translate("KMAC256");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(KMAC.class);
        assertThat(node.get().asString()).isEqualTo("KMAC256");
    }

    @Test
    void blake2bMacIsMapped() {
        Optional<INode> node = translate("BLAKE2BMAC");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(BLAKE2b.class);
        assertThat(node.get().asString()).isEqualTo("BLAKE2b-512");
    }

    @Test
    void blake2sMacIsMapped() {
        Optional<INode> node = translate("BLAKE2SMAC");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(BLAKE2s.class);
        assertThat(node.get().asString()).isEqualTo("BLAKE2s-256");
    }

    @Test
    void unknownAlgorithmNameResolvesToEmpty() {
        assertThat(translate("NOT-A-REAL-MAC")).isEmpty();
    }
}
