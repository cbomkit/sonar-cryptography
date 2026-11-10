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
package com.ibm.engine.language.csharp;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Covers {@link CSharpTypeInference#isDefinitelyIncompatible}, which decides whether the argument
 * binder may rule out an argument for a declared parameter type.
 *
 * <p>Ruling out is only safe where both types are known and cannot overlap. The enum and struct
 * types are disjoint from each other, the class types are not, and an unknown type is never ruled
 * out.
 */
class CSharpTypeInferenceTest {

    @Test
    void twoDifferentEnumOrStructTypesAreIncompatible() {
        assertThat(
                        CSharpTypeInference.isDefinitelyIncompatible(
                                "RSASignaturePadding", "HashAlgorithmName"))
                .isTrue();
        assertThat(
                        CSharpTypeInference.isDefinitelyIncompatible(
                                "HashAlgorithmName", "RSASignaturePadding"))
                .isTrue();
        assertThat(
                        CSharpTypeInference.isDefinitelyIncompatible(
                                "RSASignaturePadding", "RSAEncryptionPadding"))
                .isTrue();
        assertThat(CSharpTypeInference.isDefinitelyIncompatible("CipherMode", "PaddingMode"))
                .isTrue();
    }

    @Test
    void theSameTypeIsCompatible() {
        assertThat(
                        CSharpTypeInference.isDefinitelyIncompatible(
                                "HashAlgorithmName", "HashAlgorithmName"))
                .isFalse();
    }

    @Test
    void classTypesInAHierarchyAreNotRuledOut() {
        // RSA is an AsymmetricAlgorithm, so these must stay possible
        assertThat(CSharpTypeInference.isDefinitelyIncompatible("RSA", "AsymmetricAlgorithm"))
                .isFalse();
        assertThat(CSharpTypeInference.isDefinitelyIncompatible("AsymmetricAlgorithm", "RSA"))
                .isFalse();
        assertThat(CSharpTypeInference.isDefinitelyIncompatible("ECDsa", "AsymmetricAlgorithm"))
                .isFalse();
    }

    @Test
    void anUnknownTypeIsNeverRuledOut() {
        assertThat(CSharpTypeInference.isDefinitelyIncompatible("Foo", "HashAlgorithmName"))
                .isFalse();
        assertThat(CSharpTypeInference.isDefinitelyIncompatible("HashAlgorithmName", "Foo"))
                .isFalse();
    }

    @Test
    void aPrimitiveIsStillRuledOutForAKnownType() {
        assertThat(CSharpTypeInference.isDefinitelyIncompatible("int", "HashAlgorithmName"))
                .isTrue();
        assertThat(CSharpTypeInference.isDefinitelyIncompatible("string", "RSASignaturePadding"))
                .isTrue();
    }
}
