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

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.Size;
import com.ibm.engine.utils.Utils;
import java.math.BigInteger;
import java.util.Optional;
import java.util.function.BiFunction;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public abstract class SizeFactory<T> {
    @Nonnull private final Size.UnitType interpretAsUnitType;

    /**
     * How string values are interpreted. {@code null} when not requested explicitly, in which case
     * the legacy unit-type-dependent behavior is kept.
     */
    @Nullable private final StringInterpretation stringInterpretation;

    protected SizeFactory() {
        this.interpretAsUnitType = Size.UnitType.BYTE;
        this.stringInterpretation = null;
    }

    protected SizeFactory(@Nonnull Size.UnitType interpretAsUnitType) {
        this.interpretAsUnitType = interpretAsUnitType;
        this.stringInterpretation = null;
    }

    protected SizeFactory(
            @Nonnull Size.UnitType interpretAsUnitType,
            @Nonnull StringInterpretation stringInterpretation) {
        this.interpretAsUnitType = interpretAsUnitType;
        this.stringInterpretation = stringInterpretation;
    }

    @Nonnull
    protected Optional<IValue<T>> apply(
            @Nonnull ResolvedValue<Object, T> objectTResolvedValue,
            @Nonnull BiFunction<Integer, T, IValue<T>> createSize) {
        final Optional<Integer> bitSize =
                this.stringInterpretation == null
                        ? legacyBitSize(objectTResolvedValue)
                        : explicitBitSize(objectTResolvedValue, this.stringInterpretation);
        return bitSize.map(value -> createSize.apply(value, objectTResolvedValue.tree()));
    }

    @Nonnull
    private Optional<Integer> legacyBitSize(@Nonnull ResolvedValue<Object, T> resolvedValue) {
        return switch (this.interpretAsUnitType) {
            case BYTE -> Utils.byteSizeValueToBitSizeInteger(resolvedValue);
            case BIT -> Utils.bitSizeValueToBitSizeInteger(resolvedValue);
            case PRIME_P -> Utils.bigIntegerValueToBitSizeInteger(resolvedValue);
        };
    }

    @Nonnull
    private Optional<Integer> explicitBitSize(
            @Nonnull ResolvedValue<Object, T> resolvedValue,
            @Nonnull StringInterpretation interpretation) {
        final Object value = resolvedValue.value();
        if (value instanceof Integer i) {
            return numericToBitSize(i);
        }
        if (value instanceof String str) {
            return switch (interpretation) {
                case NUMERIC_VALUE -> parseNumericToBitSize(str);
                case BYTE_LENGTH -> Utils.byteSizeValueToBitSizeInteger(resolvedValue);
            };
        }
        return Optional.empty();
    }

    @Nonnull
    private Optional<Integer> parseNumericToBitSize(@Nonnull String str) {
        try {
            if (this.interpretAsUnitType == Size.UnitType.PRIME_P) {
                return Optional.of(new BigInteger(str).bitLength());
            }
            return numericToBitSize(Integer.parseInt(str));
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }

    @Nonnull
    private Optional<Integer> numericToBitSize(int number) {
        return switch (this.interpretAsUnitType) {
            case BIT -> Optional.of(number);
            case BYTE -> {
                try {
                    yield Optional.of(Math.multiplyExact(number, 8));
                } catch (ArithmeticException e) {
                    yield Optional.empty();
                }
            }
            // the value is the prime itself, as for numeric strings
            case PRIME_P -> Optional.of(BigInteger.valueOf(number).bitLength());
        };
    }
}
