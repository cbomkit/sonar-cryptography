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
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.ANSIX942;
import com.ibm.mapper.model.algorithms.ANSIX963;
import com.ibm.mapper.model.algorithms.ConcatenationKDF;
import com.ibm.mapper.model.algorithms.HKDF;
import com.ibm.mapper.model.algorithms.KDFCounter;
import com.ibm.mapper.model.algorithms.PBKDF1;
import com.ibm.mapper.model.algorithms.PBKDF2;
import com.ibm.mapper.model.algorithms.SSHKDF;
import com.ibm.mapper.model.algorithms.Scrypt;
import com.ibm.mapper.model.algorithms.TLSPRF;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class CxxKeyDerivationFunctionContextTranslatorTest {

    private static final DetectionLocation TEST_LOCATION =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");

    private final CxxKeyDerivationFunctionContextTranslator translator =
            new CxxKeyDerivationFunctionContextTranslator();

    private Optional<INode> translate(String value) {
        return translator.translate(
                () -> "OpenSSL",
                new ValueAction<>(value, (AstNode) null),
                new KeyDerivationFunctionContext(),
                TEST_LOCATION);
    }

    @Test
    void tls1PrfIsNotMappedToPbkdf2() {
        Optional<INode> node = translate("TLS1-PRF-SHA256");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(TLSPRF.class).isNotInstanceOf(PBKDF2.class);
        assertThat(node.get().asString()).isEqualTo("TLS-PRF-SHA-256");
    }

    @Test
    void sshkdfIsNotMappedToPbkdf2() {
        Optional<INode> node = translate("SSHKDF-SHA256");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(SSHKDF.class).isNotInstanceOf(PBKDF2.class);
        assertThat(node.get().asString()).isEqualTo("SSHKDF-SHA-256");
    }

    private static Stream<Arguments> pbkdf2Variants() {
        return Stream.of(
                Arguments.of("PBKDF2-HMAC-SHA1", "PBKDF2-SHA-1"),
                Arguments.of("PBKDF2-HMAC-SHA384", "PBKDF2-SHA-384"),
                Arguments.of("PBKDF2-HMAC-SHA512", "PBKDF2-SHA-512"),
                Arguments.of("PBKDF2-HMAC-SHA3-256", "PBKDF2-SHA3-256"),
                Arguments.of("PBKDF2-HMAC-SHA3-512", "PBKDF2-SHA3-512"),
                // SM3 and MD5 have no dedicated digest mapping: bare PBKDF2
                Arguments.of("PBKDF2-HMAC-SM3", "PBKDF2"),
                Arguments.of("PBKDF2-HMAC-MD5", "PBKDF2"),
                Arguments.of("PBKDF2-HMAC", "PBKDF2"));
    }

    @ParameterizedTest
    @MethodSource("pbkdf2Variants")
    void pbkdf2VariantsResolveToPbkdf2WithTheExpectedDigest(String value, String expectedName) {
        Optional<INode> node = translate(value);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(PBKDF2.class);
        assertThat(node.get().asString()).isEqualTo(expectedName);
    }

    private static Stream<Arguments> hkdfVariants() {
        return Stream.of(
                Arguments.of("HKDF-SHA1", "HKDF-SHA-1"),
                Arguments.of("HKDF-SHA384", "HKDF-SHA-384"),
                Arguments.of("HKDF-SHA512", "HKDF-SHA-512"),
                Arguments.of("HKDF-SHA3-256", "HKDF-SHA3-256"),
                // the TLS 1.3 KDF is HKDF-based and resolves to the same node shape
                Arguments.of("TLS13-KDF-SHA384", "HKDF-SHA-384"),
                Arguments.of("TLS13-KDF-SHA512", "HKDF-SHA-512"));
    }

    @ParameterizedTest
    @MethodSource("hkdfVariants")
    void hkdfVariantsResolveToHkdfWithTheExpectedDigest(String value, String expectedName) {
        Optional<INode> node = translate(value);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(HKDF.class);
        assertThat(node.get().asString()).isEqualTo(expectedName);
    }

    @Test
    void scryptIsMapped() {
        Optional<INode> node = translate("SCRYPT");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(Scrypt.class);
    }

    @Test
    void tls1PrfMd5Sha1IsMappedToBareTlsPrf() {
        Optional<INode> node = translate("TLS1-PRF-MD5-SHA1");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(TLSPRF.class);
        assertThat(node.get().asString()).isEqualTo("TLS-PRF");
    }

    @Test
    void tls1PrfSha384IsMapped() {
        Optional<INode> node = translate("TLS1-PRF-SHA384");
        assertThat(node).isPresent();
        assertThat(node.get().asString()).isEqualTo("TLS-PRF-SHA-384");
    }

    @Test
    void tls1PrfSha512IsMapped() {
        Optional<INode> node = translate("TLS1-PRF-SHA512");
        assertThat(node).isPresent();
        assertThat(node.get().asString()).isEqualTo("TLS-PRF-SHA-512");
    }

    private static Stream<Arguments> x963kdfVariants() {
        return Stream.of(
                Arguments.of("X963KDF-SHA1"),
                Arguments.of("X963KDF-SHA224"),
                Arguments.of("X963KDF-SHA256"),
                Arguments.of("X963KDF-SHA384"),
                Arguments.of("X963KDF-SHA512"));
    }

    @ParameterizedTest
    @MethodSource("x963kdfVariants")
    void x963kdfVariantsResolveToAnsiX963(String value) {
        Optional<INode> node = translate(value);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(ANSIX963.class);
        assertThat(node.get().asString()).isEqualTo("ANSI-KDF-X9.63");
    }

    private static Stream<Arguments> kbkdfVariants() {
        return Stream.of(
                Arguments.of("KBKDF-HMAC-SHA1"),
                Arguments.of("KBKDF-HMAC-SHA256"),
                Arguments.of("KBKDF-HMAC-SHA384"),
                Arguments.of("KBKDF-HMAC-SHA512"),
                Arguments.of("KBKDF-CMAC-AES128"),
                Arguments.of("KBKDF-CMAC-AES256"));
    }

    @ParameterizedTest
    @MethodSource("kbkdfVariants")
    void kbkdfVariantsResolveToKdfCounter(String value) {
        Optional<INode> node = translate(value);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(KDFCounter.class);
        assertThat(node.get().asString()).isEqualTo("SP800_108_CounterKDF");
    }

    @Test
    void x942kdfAsn1IsMapped() {
        Optional<INode> node = translate("X942KDF-ASN1");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(ANSIX942.class);
        assertThat(node.get().asString()).isEqualTo("ANSI-KDF-X9.42-ASN1");
    }

    @Test
    void x942kdfConcatIsMapped() {
        Optional<INode> node = translate("X942KDF-CONCAT");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(ANSIX942.class);
        assertThat(node.get().asString()).isEqualTo("ANSI-KDF-X9.42-CONCAT");
    }

    private static Stream<Arguments> sskdfVariants() {
        return Stream.of(
                Arguments.of("SSKDF"), Arguments.of("SSKDF-SHA256"), Arguments.of("SSKDF-SHA512"));
    }

    @ParameterizedTest
    @MethodSource("sskdfVariants")
    void sskdfVariantsResolveToConcatenationKdf(String value) {
        Optional<INode> node = translate(value);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(ConcatenationKDF.class);
    }

    @Test
    void sshkdfSha1IsMapped() {
        Optional<INode> node = translate("SSHKDF-SHA1");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(SSHKDF.class);
        assertThat(node.get().asString()).isEqualTo("SSHKDF-SHA-1");
    }

    @Test
    void sshkdfSha512IsMapped() {
        Optional<INode> node = translate("SSHKDF-SHA512");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(SSHKDF.class);
        assertThat(node.get().asString()).isEqualTo("SSHKDF-SHA-512");
    }

    @Test
    void krb5kdfIsMapped() {
        Optional<INode> node = translate("KRB5KDF");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(Algorithm.class);
        assertThat(node.get().asString()).isEqualTo("KRB5KDF");
    }

    private static Stream<Arguments> argon2Variants() {
        return Stream.of(
                Arguments.of("ARGON2D", "Argon2d"),
                Arguments.of("ARGON2I", "Argon2i"),
                Arguments.of("ARGON2ID", "Argon2id"));
    }

    @ParameterizedTest
    @MethodSource("argon2Variants")
    void argon2VariantsAreMapped(String value, String expectedName) {
        Optional<INode> node = translate(value);
        assertThat(node).isPresent();
        assertThat(node.get().asString()).isEqualTo(expectedName);
    }

    @Test
    void pkcs12kdfIsMapped() {
        Optional<INode> node = translate("PKCS12KDF");
        assertThat(node).isPresent();
        assertThat(node.get().asString()).isEqualTo("PKCS12KDF");
    }

    @Test
    void pvkkdfIsMapped() {
        Optional<INode> node = translate("PVKKDF");
        assertThat(node).isPresent();
        assertThat(node.get().asString()).isEqualTo("PVKKDF");
    }

    @Test
    void pbkdf1Md5IsMapped() {
        Optional<INode> node = translate("PBKDF1-MD5");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(PBKDF1.class);
        assertThat(node.get().asString()).isEqualTo("PBKDF1-MD5");
    }

    @Test
    void pbkdf1Sha1IsMapped() {
        Optional<INode> node = translate("PBKDF1-SHA1");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(PBKDF1.class);
        assertThat(node.get().asString()).isEqualTo("PBKDF1-SHA-1");
    }

    @Test
    void hmacDrbgKdfIsMapped() {
        Optional<INode> node = translate("HMAC-DRBG-KDF");
        assertThat(node).isPresent();
        assertThat(node.get().asString()).isEqualTo("HMAC-DRBG-KDF");
    }

    @Test
    void unknownAlgorithmNameResolvesToEmpty() {
        assertThat(translate("NOT-A-REAL-KDF")).isEmpty();
    }
}
