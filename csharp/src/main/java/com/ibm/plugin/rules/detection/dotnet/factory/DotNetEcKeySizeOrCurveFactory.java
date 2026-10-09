/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
package com.ibm.plugin.rules.detection.dotnet.factory;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.Curve;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.factory.IValueFactory;
import java.util.Optional;
import java.util.Set;
import javax.annotation.Nonnull;

/**
 * Reads the single argument of {@code ECDsa.Create}, {@code ECDiffieHellman.Create} and the {@code
 * ECDsaCng}/{@code ECDsaOpenSsl}/{@code ECDiffieHellmanCng}/{@code ECDiffieHellmanOpenSsl}
 * constructors, all of which accept several unrelated things in the same position.
 *
 * <p>The .NET signatures at that position are {@code int keySizeInBits}, {@code ECCurve curve},
 * {@code ECParameters parameters}, {@code string algorithm} and, for the CNG variant, {@code
 * CngKey}. They share an arity, so no matcher can separate them, and they are not separable by the
 * binder's type-directed step either, since one declared parameter can only be filled once. The
 * split therefore happens here, on the resolved value:
 *
 * <ul>
 *   <li>an {@code Integer} is the key size in bits
 *   <li>a {@code String} naming one of the {@code ECCurve.NamedCurves} members is that curve
 *   <li>any other {@code String} is a provider or algorithm name, which carries no information the
 *       rule's own action factory has not already recorded, and is discarded
 * </ul>
 *
 * <p>The named-curve list is explicit rather than a pattern such as "starts with nist or
 * brainpool". A name outside it produces nothing, so an {@code ECParameters} variable or an
 * unrecognized spelling leaves the curve absent instead of recording a made-up one. The list is the
 * full set of static properties of {@code ECCurve.NamedCurves} per the official API reference.
 *
 * <p>Curves that reach the call through {@code ECCurve.CreateFromFriendlyName} or {@code
 * ECCurve.CreateFromValue} are not resolved here; those are calls, not constant members, and are
 * covered by a depending rule on the same parameter.
 */
public final class DotNetEcKeySizeOrCurveFactory<T> implements IValueFactory<T> {

    @Nonnull
    private static final Set<String> NAMED_CURVES =
            Set.of(
                    "nistP256",
                    "nistP384",
                    "nistP521",
                    "brainpoolP160r1",
                    "brainpoolP160t1",
                    "brainpoolP192r1",
                    "brainpoolP192t1",
                    "brainpoolP224r1",
                    "brainpoolP224t1",
                    "brainpoolP256r1",
                    "brainpoolP256t1",
                    "brainpoolP320r1",
                    "brainpoolP320t1",
                    "brainpoolP384r1",
                    "brainpoolP384t1",
                    "brainpoolP512r1",
                    "brainpoolP512t1");

    @Nonnull
    @Override
    public Optional<IValue<T>> apply(@Nonnull ResolvedValue<Object, T> resolvedValue) {
        final Object value = resolvedValue.value();
        if (value instanceof Integer bits) {
            return Optional.of(new KeySize<>(bits, Size.UnitType.BIT, resolvedValue.tree()));
        }
        if (value instanceof String name && isNamedCurve(name)) {
            return Optional.of(new Curve<>(name, resolvedValue.tree()));
        }
        return Optional.empty();
    }

    private static boolean isNamedCurve(@Nonnull String name) {
        final String trimmed = name.trim();
        return NAMED_CURVES.stream().anyMatch(curve -> curve.equalsIgnoreCase(trimmed));
    }
}
