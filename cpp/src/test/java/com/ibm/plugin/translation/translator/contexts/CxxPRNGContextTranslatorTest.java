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
import com.ibm.engine.model.context.PRNGContext;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class CxxPRNGContextTranslatorTest {

    private static final DetectionLocation TEST_LOCATION =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");

    private final CxxPRNGContextTranslator translator = new CxxPRNGContextTranslator();

    private Optional<INode> translate(String value) {
        return translator.translate(
                () -> "OpenSSL",
                new ValueAction<>(value, (AstNode) null),
                new PRNGContext(),
                TEST_LOCATION);
    }

    private static Stream<Arguments> bareAlgorithmVariants() {
        return Stream.of(
                Arguments.of("RAND"),
                Arguments.of("RAND-PSEUDO"),
                Arguments.of("CTR-DRBG"),
                Arguments.of("HASH-DRBG"),
                Arguments.of("HMAC-DRBG"),
                Arguments.of("SEED-SRC"),
                Arguments.of("JITTER"),
                Arguments.of("TEST-RAND"));
    }

    @ParameterizedTest
    @MethodSource("bareAlgorithmVariants")
    void bareAlgorithmNamesResolveToThemselves(String value) {
        Optional<INode> node = translate(value);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(Algorithm.class);
        assertThat(node.get().asString()).isEqualTo(value);
    }

    private static Stream<Arguments> ctrDrbgAesVariants() {
        return Stream.of(
                Arguments.of("CTR-DRBG-AES128", "AES-128"),
                Arguments.of("CTR-DRBG-AES192", "AES-192"),
                Arguments.of("CTR-DRBG-AES256", "AES-256"));
    }

    @ParameterizedTest
    @MethodSource("ctrDrbgAesVariants")
    void ctrDrbgVariantsResolveToTheUnderlyingAes(String value, String expectedName) {
        Optional<INode> node = translate(value);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(AES.class);
        assertThat(node.get().asString()).isEqualTo(expectedName);
    }

    @Test
    void hashDrbgSha1ResolvesToSha() {
        Optional<INode> node = translate("HASH-DRBG-SHA1");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(SHA.class);
        assertThat(node.get().asString()).isEqualTo("SHA-1");
    }

    private static Stream<Arguments> hashDrbgSha2Variants() {
        return Stream.of(
                Arguments.of("HASH-DRBG-SHA256", "SHA-256"),
                Arguments.of("HASH-DRBG-SHA384", "SHA-384"),
                Arguments.of("HASH-DRBG-SHA512", "SHA-512"));
    }

    @ParameterizedTest
    @MethodSource("hashDrbgSha2Variants")
    void hashDrbgVariantsResolveToTheUnderlyingSha2(String value, String expectedName) {
        Optional<INode> node = translate(value);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(SHA2.class);
        assertThat(node.get().asString()).isEqualTo(expectedName);
    }

    @Test
    void hmacDrbgSha1ResolvesToSha() {
        Optional<INode> node = translate("HMAC-DRBG-SHA1");
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(SHA.class);
        assertThat(node.get().asString()).isEqualTo("SHA-1");
    }

    private static Stream<Arguments> hmacDrbgSha2Variants() {
        return Stream.of(
                Arguments.of("HMAC-DRBG-SHA256", "SHA-256"),
                Arguments.of("HMAC-DRBG-SHA384", "SHA-384"),
                Arguments.of("HMAC-DRBG-SHA512", "SHA-512"));
    }

    @ParameterizedTest
    @MethodSource("hmacDrbgSha2Variants")
    void hmacDrbgVariantsResolveToTheUnderlyingSha2(String value, String expectedName) {
        Optional<INode> node = translate(value);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(SHA2.class);
        assertThat(node.get().asString()).isEqualTo(expectedName);
    }

    private static Stream<Arguments> entropySeedingOperations() {
        return Stream.of(
                Arguments.of("RAND-SEED"), Arguments.of("RAND-ADD"), Arguments.of("RAND-POLL"));
    }

    @ParameterizedTest
    @MethodSource("entropySeedingOperations")
    void entropySeedingOperationsAreNotDistinctAlgorithms(String value) {
        assertThat(translate(value)).isEmpty();
    }

    @Test
    void unknownAlgorithmNameResolvesToEmpty() {
        assertThat(translate("NOT-A-REAL-PRNG")).isEmpty();
    }
}
