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
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.Ed25519;
import com.ibm.mapper.model.algorithms.Ed448;
import com.ibm.mapper.model.algorithms.MLDSA;
import com.ibm.mapper.model.algorithms.MLKEM;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SM2;
import com.ibm.mapper.model.algorithms.SPHINCSPlus;
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

class CxxKeyContextTranslatorTest {

    private static final DetectionLocation TEST_LOCATION =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");

    private final CxxKeyContextTranslator translator = new CxxKeyContextTranslator();

    private Optional<INode> translate(String value) {
        return translator.translate(
                () -> "OpenSSL",
                new ValueAction<>(value, (AstNode) null),
                new KeyContext(),
                TEST_LOCATION);
    }

    @Test
    void arbitraryRsaBitLengthIsMappedToRsaWithThatKeyLength() {
        Optional<INode> node = translate("RSA-2048");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(RSA.class);
        assertThat(node.get().asString()).isEqualTo("RSA-2048");
    }

    @Test
    void bareRsaIsMapped() {
        Optional<INode> node = translate("RSA");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(RSA.class);
    }

    @Test
    void rsaPssIsNotTreatedAsAnRsaBitLength() {
        Optional<INode> node = translate("RSA-PSS");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(RSA.class);
    }

    @Test
    void arbitraryDsaBitLengthResolvesToBareDsa() {
        Optional<INode> node = translate("DSA-2048");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(DSA.class);
        assertThat(node.get().asString()).isEqualTo("DSA");
    }

    @Test
    void bareDsaIsMapped() {
        Optional<INode> node = translate("DSA");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(DSA.class);
    }

    @Test
    void bareEcIsMappedToEcdsaWithNoCurve() {
        Optional<INode> node = translate("EC");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(ECDSA.class);
    }

    private static Stream<Arguments> ecCurveVariants() {
        return Stream.of(
                Arguments.of("EC-P192", "ECDSA-secp192r1"),
                Arguments.of("EC-P224", "ECDSA-secp224r1"),
                Arguments.of("EC-P256", "ECDSA-secp256r1"),
                Arguments.of("EC-P384", "ECDSA-secp384r1"),
                Arguments.of("EC-P521", "ECDSA-secp521r1"),
                Arguments.of("EC-SECP256K1", "ECDSA-secp256k1"),
                Arguments.of("EC-BRAINPOOLP256R1", "ECDSA-brainpoolP256r1"),
                Arguments.of("EC-BRAINPOOLP384R1", "ECDSA-brainpoolP384r1"),
                Arguments.of("EC-BRAINPOOLP512R1", "ECDSA-brainpoolP512r1"));
    }

    @ParameterizedTest
    @MethodSource("ecCurveVariants")
    void ecCurveVariantsResolveToEcdsaWithTheExpectedCurve(String value, String expectedName) {
        Optional<INode> node = translate(value);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(ECDSA.class);
        assertThat(node.get().asString()).isEqualTo(expectedName);
    }

    @Test
    void bareDhIsMapped() {
        Optional<INode> node = translate("DH");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(DH.class);
    }

    @Test
    void dh2048IsMappedToDh() {
        Optional<INode> node = translate("DH-2048");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(DH.class);
    }

    @Test
    void dh4096IsMappedToDh() {
        Optional<INode> node = translate("DH-4096");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(DH.class);
    }

    @Test
    void ed25519IsMapped() {
        Optional<INode> node = translate("ED25519");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(Ed25519.class);
    }

    @Test
    void ed448IsMapped() {
        Optional<INode> node = translate("ED448");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(Ed448.class);
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

    private static Stream<Arguments> mldsaVariants() {
        return Stream.of(
                Arguments.of("ML-DSA-44", "ML-DSA-44"),
                Arguments.of("ML-DSA-65", "ML-DSA-65"),
                Arguments.of("ML-DSA-87", "ML-DSA-87"));
    }

    @ParameterizedTest
    @MethodSource("mldsaVariants")
    void mldsaVariantsResolveToMldsaOfTheExpectedParameterSet(String value, String expectedName) {
        Optional<INode> node = translate(value);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(MLDSA.class);
        assertThat(node.get().asString()).isEqualTo(expectedName);
    }

    private static Stream<Arguments> slhdsaVariants() {
        return Stream.of(
                Arguments.of("SLH-DSA-SHA2-128F", "SLH-DSA-SHA2-128F"),
                Arguments.of("SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128S"),
                Arguments.of("SLH-DSA-SHAKE-128F", "SLH-DSA-SHAKE-128F"),
                Arguments.of("SLH-DSA-SHAKE-128S", "SLH-DSA-SHAKE-128S"),
                Arguments.of("SLH-DSA-SHA2-192F", "SLH-DSA-SHA2-192F"),
                Arguments.of("SLH-DSA-SHA2-192S", "SLH-DSA-SHA2-192S"),
                Arguments.of("SLH-DSA-SHAKE-192F", "SLH-DSA-SHAKE-192F"),
                Arguments.of("SLH-DSA-SHAKE-192S", "SLH-DSA-SHAKE-192S"),
                Arguments.of("SLH-DSA-SHA2-256F", "SLH-DSA-SHA2-256F"),
                Arguments.of("SLH-DSA-SHA2-256S", "SLH-DSA-SHA2-256S"),
                Arguments.of("SLH-DSA-SHAKE-256F", "SLH-DSA-SHAKE-256F"),
                Arguments.of("SLH-DSA-SHAKE-256S", "SLH-DSA-SHAKE-256S"));
    }

    @ParameterizedTest
    @MethodSource("slhdsaVariants")
    void slhdsaVariantsResolveToSphincsPlusOfTheExpectedParameterSet(
            String value, String expectedName) {
        Optional<INode> node = translate(value);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(SPHINCSPlus.class);
        assertThat(node.get().asString()).isEqualTo(expectedName);
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
    void sm2IsMapped() {
        Optional<INode> node = translate("SM2");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(SM2.class);
    }

    @Test
    void unknownAlgorithmNameResolvesToEmpty() {
        assertThat(translate("NOT-A-REAL-ALGORITHM")).isEmpty();
    }
}
