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
import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.algorithms.MLKEM;
import com.ibm.mapper.model.algorithms.SM2;
import com.ibm.mapper.model.algorithms.SecP256r1MLKEM768;
import com.ibm.mapper.model.algorithms.SecP384r1MLKEM1024;
import com.ibm.mapper.model.algorithms.X25519;
import com.ibm.mapper.model.algorithms.X25519MLKEM768;
import com.ibm.mapper.model.algorithms.X448;
import com.ibm.mapper.model.algorithms.X448MLKEM1024;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class CxxKeyAgreementContextTranslatorTest {

    private static final DetectionLocation TEST_LOCATION =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");

    private final CxxKeyAgreementContextTranslator translator =
            new CxxKeyAgreementContextTranslator();

    private Optional<INode> translate(String value) {
        return translator.translate(
                () -> "OpenSSL",
                new ValueAction<>(value, (AstNode) null),
                new KeyAgreementContext(),
                TEST_LOCATION);
    }

    private static Stream<Arguments> dhVariants() {
        return Stream.of(
                Arguments.of("DH"),
                Arguments.of("DH-2048"),
                Arguments.of("DH-3072"),
                Arguments.of("DH-4096"));
    }

    @ParameterizedTest
    @MethodSource("dhVariants")
    void dhVariantsResolveToDh(String value) {
        Optional<INode> node = translate(value);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(DH.class);
    }

    private static Stream<Arguments> ecdhVariants() {
        return Stream.of(
                Arguments.of("ECDH"),
                Arguments.of("ECDH-P256"),
                Arguments.of("ECDH-P384"),
                Arguments.of("ECDH-P521"),
                Arguments.of("ECDH-SECP256K1"));
    }

    @ParameterizedTest
    @MethodSource("ecdhVariants")
    void ecdhVariantsResolveToEcdh(String value) {
        Optional<INode> node = translate(value);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(ECDH.class);
    }

    @Test
    void x25519IsMapped() {
        Optional<INode> node = translate("X25519");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(X25519.class);
    }

    @Test
    void x448IsMapped() {
        Optional<INode> node = translate("X448");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(X448.class);
    }

    private static Stream<Arguments> mlkemVariants() {
        return Stream.of(
                Arguments.of("ML-KEM-512", 512),
                Arguments.of("ML-KEM-768", 768),
                Arguments.of("ML-KEM-1024", 1024));
    }

    @ParameterizedTest
    @MethodSource("mlkemVariants")
    void mlkemVariantsResolveToMlkemOfTheExpectedParameterSet(String value, int parameterSet) {
        Optional<INode> node = translate(value);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(MLKEM.class);
        assertThat(node.get().asString()).isEqualTo("ML-KEM-" + parameterSet);
    }

    @Test
    void x25519Mlkem768HybridIsMapped() {
        Optional<INode> node = translate("X25519MLKEM768");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(X25519MLKEM768.class);
    }

    @Test
    void x448Mlkem1024HybridIsMapped() {
        Optional<INode> node = translate("X448MLKEM1024");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(X448MLKEM1024.class);
    }

    @Test
    void secp256r1Mlkem768HybridIsMapped() {
        Optional<INode> node = translate("SECP256R1MLKEM768");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(SecP256r1MLKEM768.class);
    }

    @Test
    void secp384r1Mlkem1024HybridIsMapped() {
        Optional<INode> node = translate("SECP384R1MLKEM1024");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(SecP384r1MLKEM1024.class);
    }

    @Test
    void sm2KeyExchangeIsMapped() {
        Optional<INode> node = translate("SM2");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(SM2.class);
    }

    @Test
    void unknownAlgorithmNameResolvesToEmpty() {
        assertThat(translate("NOT-A-REAL-KEY-AGREEMENT")).isEmpty();
    }
}
