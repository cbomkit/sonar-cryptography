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
package com.ibm.output.cyclondx.builder;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;
import javax.annotation.Nonnull;
import org.cyclonedx.model.component.crypto.enums.Mode;
import org.cyclonedx.model.component.crypto.enums.Padding;

public final class Utils {

    private Utils() {
        // nothing
    }

    public static @Nonnull Optional<Mode> parseStringToMode(@Nonnull String string) {
        return Arrays.stream(org.cyclonedx.model.component.crypto.enums.Mode.values())
                .filter(k -> k.name().equalsIgnoreCase(string))
                .findFirst();
    }

    public static @Nonnull Optional<Padding> parseStringToPadding(@Nonnull String string) {
        return Arrays.stream(org.cyclonedx.model.component.crypto.enums.Padding.values())
                .filter(k -> k.name().equalsIgnoreCase(string))
                .findFirst();
    }

    @Nonnull
    public static <T> Predicate<T> distinctByKey(
            @Nonnull Function<? super T, Object> keyExtractor) {
        Map<Object, Boolean> map = new ConcurrentHashMap<>();
        return t -> map.putIfAbsent(keyExtractor.apply(t), Boolean.TRUE) == null;
    }
}
