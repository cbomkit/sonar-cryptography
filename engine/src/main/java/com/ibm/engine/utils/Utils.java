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
package com.ibm.engine.utils;

import com.ibm.engine.detection.ResolvedValue;
import java.math.BigInteger;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class Utils {

    private Utils() {
        // nothing
    }

    /**
     * Converts a hexadecimal string to a BigInteger.
     *
     * @param hex the hexadecimal string to convert
     * @return an optional of the converted BigInteger
     */
    @Nonnull
    public static Optional<BigInteger> hexToBigint(@Nonnull String hex) {
        if (hex.startsWith("0x")) {
            hex = hex.substring(2);
        }
        return Optional.of(new BigInteger(hex, 16));
    }

    /**
     * This method converts an integer representing the number of bytes to an integer representing
     * the number of bits. The conversion is done by multiplying the byte size by 8.
     *
     * @param byteSize the integer representing the number of bytes to convert to bits
     * @return the integer representing the number of bits obtained by multiplying the byte size by
     *     8
     */
    @Nonnull
    private static Integer byteSizeToBitSize(@Nonnull Integer byteSize) {
        return byteSize * 8;
    }

    /**
     * This method takes in a resolved value object and returns an optional integer that represents
     * the size of the value in bits. The method first checks if the value is an instance of
     * Integer. If it is, then the method uses the Utils.byteSizeToBitSize method to convert the
     * integer's byte size to its bit size and returns an optional of that value. If the value is a
     * string, the method uses the same method to convert the length of the string's byte
     * representation to its bit size and returns an optional of that value. If the value is neither
     * an integer nor a string, the method returns an empty optional.
     *
     * @param resolvedValue - Resolved value object
     * @return Optional<Integer> - Integer representing size of value in bits or empty optional
     */
    @Nonnull
    public static <O, T> Optional<Integer> byteSizeValueToBitSizeInteger(
            @Nonnull ResolvedValue<O, T> resolvedValue) {
        if (resolvedValue.value() instanceof Integer i) {
            return Optional.of(Utils.byteSizeToBitSize(i));
        } else if (resolvedValue.value() instanceof String str) {
            return Optional.of(Utils.byteSizeToBitSize(str.getBytes().length));
        } else {
            return Optional.empty();
        }
    }

    /**
     * This method takes a resolved value of type O and T, and returns an Optional<Integer>
     * containing the bit size of the BigInteger representation of the resolved value.
     *
     * <p>If the resolved value is a String instance, it will be converted to a BigInteger using the
     * string constructor, and then its bit length will be returned in an Optional<Integer>.
     *
     * <p>If the resolved value is not a String instance, it will return an empty Optional<Integer>.
     *
     * <p>
     *
     * @param resolvedValue the resolved value of type O and T.
     * @return an Optional<Integer> containing the bit size of the BigInteger representation of the
     *     resolved value, or an empty Optional<Integer> if the resolved value is not a String
     *     instance.
     */
    @Nonnull
    public static <O, T> Optional<Integer> bigIntegerValueToBitSizeInteger(
            @Nonnull ResolvedValue<O, T> resolvedValue) {
        if (resolvedValue.value() instanceof String i) {
            return Optional.of((new BigInteger(i).bitLength()));
        } else {
            return Optional.empty();
        }
    }

    /**
     * @param resolvedValue The resolved value of type O and T to convert to an integer.
     * @return An optional containing the number of bits required for the given value or empty if
     *     the resolved value cannot be converted to an integer.
     */
    @Nonnull
    public static <O, T> Optional<Integer> bitSizeValueToBitSizeInteger(
            @Nonnull ResolvedValue<O, T> resolvedValue) {
        if (resolvedValue.value() instanceof Integer i) {
            return Optional.of(i);
        } else if (resolvedValue.value() instanceof String str) {
            return Optional.of(Utils.byteSizeToBitSize(str.getBytes().length));
        } else {
            return Optional.empty();
        }
    }
}
