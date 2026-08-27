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
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.EdDSA;
import com.ibm.mapper.model.algorithms.MLDSA;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.RSAssaPSS;
import com.ibm.mapper.model.algorithms.SM2;
import com.ibm.mapper.model.algorithms.SPHINCSPlus;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class CxxSignatureContextTranslatorTest {

    private static final DetectionLocation TEST_LOCATION =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");

    private final CxxSignatureContextTranslator translator = new CxxSignatureContextTranslator();

    private Optional<INode> translate(String value) {
        return translator.translate(
                () -> "OpenSSL",
                new ValueAction<>(value, (AstNode) null),
                new SignatureContext(),
                TEST_LOCATION);
    }

    private static Stream<Arguments> rsaPssVariants() {
        return Stream.of(
                Arguments.of("RSA-PSS-SHA256"),
                Arguments.of("RSA-PSS-SHA384"),
                Arguments.of("RSA-PSS-SHA512"),
                Arguments.of("RSA-PSS-SHA1"),
                // an unrecognized digest suffix still resolves to a bare RSA-PSS
                Arguments.of("RSA-PSS-UNKNOWN"));
    }

    @ParameterizedTest
    @MethodSource("rsaPssVariants")
    void rsaPssVariantsResolveToRsAssaPss(String value) {
        Optional<INode> node = translate(value);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(RSAssaPSS.class);
    }

    private static Stream<Arguments> rsaPkcs1Variants() {
        return Stream.of(
                Arguments.of("RSA-SHA1", "RSA-PKCS1-1.5-SHA-1"),
                Arguments.of("RSA-SHA224", "RSA-PKCS1-1.5-SHA-224"),
                Arguments.of("RSA-SHA256", "RSA-PKCS1-1.5-SHA-256"),
                Arguments.of("RSA-SHA384", "RSA-PKCS1-1.5-SHA-384"),
                Arguments.of("RSA-SHA512", "RSA-PKCS1-1.5-SHA-512"),
                // an unrecognized digest suffix still resolves to a bare RSA-PKCS1-1.5
                Arguments.of("RSA-UNKNOWN", "RSA-PKCS1-1.5"));
    }

    @ParameterizedTest
    @MethodSource("rsaPkcs1Variants")
    void rsaVariantsResolveToRsaWithTheExpectedDigest(String value, String expectedName) {
        Optional<INode> node = translate(value);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(RSA.class);
        assertThat(node.get().asString()).isEqualTo(expectedName);
    }

    private static Stream<Arguments> dsaVariants() {
        return Stream.of(
                Arguments.of("DSA-SHA1", "DSA-SHA-1"),
                Arguments.of("DSA-SHA224", "DSA-SHA-224"),
                Arguments.of("DSA-SHA256", "DSA-SHA-256"),
                Arguments.of("DSA-SHA384", "DSA-SHA-384"),
                Arguments.of("DSA-SHA512", "DSA-SHA-512"),
                // an unrecognized digest suffix still resolves to a bare DSA
                Arguments.of("DSA-UNKNOWN", "DSA"));
    }

    @ParameterizedTest
    @MethodSource("dsaVariants")
    void dsaVariantsResolveToDsaWithTheExpectedDigest(String value, String expectedName) {
        Optional<INode> node = translate(value);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(DSA.class);
        assertThat(node.get().asString()).isEqualTo(expectedName);
    }

    private static Stream<Arguments> ecdsaVariants() {
        return Stream.of(
                Arguments.of("ECDSA-SHA1", "ECDSA-SHA-1"),
                Arguments.of("ECDSA-SHA3-256", "ECDSA-SHA3-256"),
                Arguments.of("ECDSA-SHA3-384", "ECDSA-SHA3-384"),
                Arguments.of("ECDSA-SHA3-512", "ECDSA-SHA3-512"),
                Arguments.of("ECDSA-SHA224", "ECDSA-SHA-224"),
                Arguments.of("ECDSA-SHA256", "ECDSA-SHA-256"),
                Arguments.of("ECDSA-SHA384", "ECDSA-SHA-384"),
                Arguments.of("ECDSA-SHA512", "ECDSA-SHA-512"),
                // an unrecognized digest suffix still resolves to a bare ECDSA
                Arguments.of("ECDSA-UNKNOWN", "ECDSA"));
    }

    @ParameterizedTest
    @MethodSource("ecdsaVariants")
    void ecdsaVariantsResolveToEcdsaWithTheExpectedDigest(String value, String expectedName) {
        Optional<INode> node = translate(value);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(ECDSA.class);
        assertThat(node.get().asString()).isEqualTo(expectedName);
    }

    @Test
    void ed25519ResolvesToEddsa() {
        Optional<INode> node = translate("ED25519");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(EdDSA.class);
    }

    @Test
    void ed448ResolvesToEddsa() {
        Optional<INode> node = translate("ED448");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(EdDSA.class);
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

    @Test
    void slhdsaParameterSetIsExtractedFromTheAlgorithmName() {
        Optional<INode> node = translate("SLH-DSA-SHA2-128F");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(SPHINCSPlus.class);
        assertThat(node.get().asString()).isEqualTo("SLH-DSA-SHA2-128F");
    }

    @Test
    void sm2IsMapped() {
        Optional<INode> node = translate("SM2");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(SM2.class);
    }

    @Test
    void unknownAlgorithmNameResolvesToEmpty() {
        assertThat(translate("NOT-A-REAL-SIGNATURE-ALGORITHM")).isEmpty();
    }
}
