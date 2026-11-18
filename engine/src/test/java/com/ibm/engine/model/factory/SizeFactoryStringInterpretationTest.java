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
package com.ibm.engine.model.factory;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.DigestSize;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.Size.UnitType;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class SizeFactoryStringInterpretationTest {

    private static final String TREE = "tree";

    private static ResolvedValue<Object, String> resolved(Object value) {
        return new ResolvedValue<>(value, TREE);
    }

    private static Optional<Integer> digestBits(
            ResolvedValue<Object, String> value, UnitType unit, StringInterpretation mode) {
        return sizeOf(new DigestSizeFactory<String>(unit, mode).apply(value), DigestSize.class);
    }

    private static Optional<Integer> keyBits(
            ResolvedValue<Object, String> value, UnitType unit, StringInterpretation mode) {
        return sizeOf(new KeySizeFactory<String>(unit, mode).apply(value), KeySize.class);
    }

    private static Optional<Integer> sizeOf(
            Optional<IValue<String>> result, Class<? extends Size> expectedType) {
        result.ifPresent(v -> assertThat(v).isInstanceOf(expectedType));
        return result.map(v -> ((Size<?>) v).getValue());
    }

    @Test
    void numericValueInBitsUsesParsedValueAsBits() {
        assertThat(digestBits(resolved("256"), UnitType.BIT, StringInterpretation.NUMERIC_VALUE))
                .contains(256);
    }

    @Test
    void numericValueInBytesConvertsParsedValueToBits() {
        assertThat(digestBits(resolved("32"), UnitType.BYTE, StringInterpretation.NUMERIC_VALUE))
                .contains(256);
    }

    @Test
    void byteLengthCountsContentBytesRegardlessOfUnit() {
        assertThat(keyBits(resolved("256"), UnitType.BYTE, StringInterpretation.BYTE_LENGTH))
                .contains(24);
        assertThat(keyBits(resolved("256"), UnitType.BIT, StringInterpretation.BYTE_LENGTH))
                .contains(24);
    }

    @Test
    void byteLengthCountsNonNumericContent() {
        assertThat(keyBits(resolved("secret"), UnitType.BYTE, StringInterpretation.BYTE_LENGTH))
                .contains(48);
    }

    @Test
    void numericValueDoesNotFallBackToByteLengthOnInvalidInput() {
        assertThat(digestBits(resolved("abc"), UnitType.BIT, StringInterpretation.NUMERIC_VALUE))
                .isEmpty();
        assertThat(digestBits(resolved(""), UnitType.BIT, StringInterpretation.NUMERIC_VALUE))
                .isEmpty();
        assertThat(digestBits(resolved("2.5"), UnitType.BYTE, StringInterpretation.NUMERIC_VALUE))
                .isEmpty();
    }

    @Test
    void numericValueReturnsEmptyOnStringOverflow() {
        assertThat(
                        digestBits(
                                resolved("99999999999"),
                                UnitType.BIT,
                                StringInterpretation.NUMERIC_VALUE))
                .isEmpty();
    }

    @Test
    void numericValueInBytesReturnsEmptyOnBitConversionOverflow() {
        // fits in an int, but multiplying by 8 does not
        assertThat(
                        digestBits(
                                resolved(String.valueOf(Integer.MAX_VALUE)),
                                UnitType.BYTE,
                                StringInterpretation.NUMERIC_VALUE))
                .isEmpty();
        assertThat(
                        digestBits(
                                resolved(Integer.MAX_VALUE),
                                UnitType.BYTE,
                                StringInterpretation.NUMERIC_VALUE))
                .isEmpty();
    }

    @Test
    void integerValuesUseTheUnitType() {
        assertThat(digestBits(resolved(32), UnitType.BYTE, StringInterpretation.NUMERIC_VALUE))
                .contains(256);
        assertThat(digestBits(resolved(256), UnitType.BIT, StringInterpretation.BYTE_LENGTH))
                .contains(256);
    }

    @Test
    void primeIsMeasuredByBitLengthForIntegersAndNumericStrings() {
        assertThat(keyBits(resolved(65537), UnitType.PRIME_P, StringInterpretation.NUMERIC_VALUE))
                .contains(17);
        assertThat(keyBits(resolved("65537"), UnitType.PRIME_P, StringInterpretation.NUMERIC_VALUE))
                .contains(17);
        assertThat(
                        keyBits(
                                resolved("340282366920938463463374607431768211507"),
                                UnitType.PRIME_P,
                                StringInterpretation.NUMERIC_VALUE))
                .contains(129);
    }

    @Test
    void unsupportedValueTypesReturnEmpty() {
        assertThat(digestBits(resolved(1.5d), UnitType.BIT, StringInterpretation.NUMERIC_VALUE))
                .isEmpty();
        assertThat(keyBits(resolved(true), UnitType.BYTE, StringInterpretation.BYTE_LENGTH))
                .isEmpty();
    }

    @Test
    void constructorsWithoutInterpretationKeepExistingBehavior() {
        // strings are measured by their byte length, whatever the unit; nothing is parsed
        assertThat(
                        sizeOf(
                                new DigestSizeFactory<String>(UnitType.BIT).apply(resolved("256")),
                                DigestSize.class))
                .contains(24);
        assertThat(
                        sizeOf(
                                new DigestSizeFactory<String>(UnitType.BIT).apply(resolved("abc")),
                                DigestSize.class))
                .contains(24);
        assertThat(sizeOf(new KeySizeFactory<String>().apply(resolved("256")), KeySize.class))
                .contains(24);
        // integers use the unit
        assertThat(
                        sizeOf(
                                new DigestSizeFactory<String>(UnitType.BIT).apply(resolved(256)),
                                DigestSize.class))
                .contains(256);
        assertThat(sizeOf(new KeySizeFactory<String>().apply(resolved(16)), KeySize.class))
                .contains(128);
    }
}
