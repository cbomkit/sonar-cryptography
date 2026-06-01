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

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.AlgorithmParameter;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.DetectionContext;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("java:S3457")
public class DetectionStoreLogger<R, T, S, P> {
    private static final Logger LOGGER = LoggerFactory.getLogger(DetectionStoreLogger.class);

    public void print(@Nonnull DetectionStore<R, T, S, P> rootDetectionStore) {
        printDstoreValues(0, List.of(rootDetectionStore));
    }

    private static final int TRUNCATE_SIZE_FOR_LONG_NUMBERS = 6;

    private void printDstoreValues(
            int tabs, @Nonnull List<DetectionStore<R, T, S, P>> detectionStores) {
        detectionStores.forEach(
                store -> {
                    store.getActionValue()
                            .ifPresent(
                                    value ->
                                            LOGGER.debug(
                                                    "[id: "
                                                            + store.getStoreId()
                                                                    .toString()
                                                                    .substring(0, 5)
                                                            + ", bundle: "
                                                            + store.getDetectionRule()
                                                                    .bundle()
                                                                    .getIdentifier()
                                                            + ", level: "
                                                            + store.getLevel()
                                                            + ", hash: "
                                                            + getFormattedNumericString(
                                                                    store.hashCode())
                                                            + "] "
                                                            + "   ".repeat(Math.max(0, tabs))
                                                            + (tabs > 0 ? "└─ " : "")
                                                            + "("
                                                            + getDetectionValueContextMessage(
                                                                    store
                                                                            .getDetectionValueContext())
                                                            + ", "
                                                            + value.getClass().getSimpleName()
                                                            + valueSpecificString(value)
                                                            + ") "
                                                            + value.asString()));

                    final Set<Integer> visitedChildren = new HashSet<>();
                    store.detectionValuesForEachParameter(
                            (i, values) -> {
                                values.forEach(
                                        value ->
                                                LOGGER.debug(
                                                        "[id: "
                                                                + store.getStoreId()
                                                                        .toString()
                                                                        .substring(0, 5)
                                                                + ", bundle: "
                                                                + store.getDetectionRule()
                                                                        .bundle()
                                                                        .getIdentifier()
                                                                + ", level: "
                                                                + store.getLevel()
                                                                + ", hash: "
                                                                + getFormattedNumericString(
                                                                        store.hashCode())
                                                                + "] "
                                                                + "   ".repeat(Math.max(0, tabs))
                                                                + (tabs > 0 ? "└─ " : "")
                                                                + "("
                                                                + getDetectionValueContextMessage(
                                                                        store
                                                                                .getDetectionValueContext())
                                                                + ", "
                                                                + value.getClass().getSimpleName()
                                                                + valueSpecificString(value)
                                                                + ") "
                                                                + value.asString()));
                                store.getChildrenForParameterWithId(i)
                                        .ifPresent(
                                                children -> {
                                                    visitedChildren.add(i);
                                                    printDstoreValues(tabs + 1, children);
                                                });
                            });

                    printDstoreValues(tabs + 1, store.getChildrenForMethod());
                    store.childrenForEachParameter(
                            (i, childStore) -> {
                                if (!visitedChildren.contains(i)) {
                                    printDstoreValues(tabs + 1, childStore);
                                }
                            });
                });
    }

    @Nonnull
    private String valueSpecificString(@Nonnull IValue<T> value) {
        if (value instanceof Size<T> keySize) {
            return "<" + keySize.getUnitType().name().toLowerCase() + ">";
        } else if (value instanceof AlgorithmParameter<T> algorithmParameter) {
            return "<" + algorithmParameter.getKind() + ">";
        }
        return "";
    }

    @Nonnull
    private String getDetectionValueContextMessage(
            @Nonnull DetectionContext detectionValueContext) {
        return detectionValueContext.getClass().getSimpleName() + "<" + detectionValueContext + ">";
    }

    @Nonnull
    String getFormattedNumericString(int hashInt) {
        String res = "";
        if (hashInt >= 0) {
            res += "";
        }
        res += Integer.toString(hashInt);

        if (DetectionStoreLogger.TRUNCATE_SIZE_FOR_LONG_NUMBERS < 3) {
            throw new IllegalArgumentException("Max characters must be greater than or equal to 3");
        } else if (res.length() > DetectionStoreLogger.TRUNCATE_SIZE_FOR_LONG_NUMBERS) {
            res = res.substring(0, DetectionStoreLogger.TRUNCATE_SIZE_FOR_LONG_NUMBERS - 1) + "…";
        } else if (res.length() < DetectionStoreLogger.TRUNCATE_SIZE_FOR_LONG_NUMBERS) {
            res +=
                    StringUtils.repeat(
                            " ",
                            DetectionStoreLogger.TRUNCATE_SIZE_FOR_LONG_NUMBERS - res.length());
        }
        if (res.length() > DetectionStoreLogger.TRUNCATE_SIZE_FOR_LONG_NUMBERS) {
            res = res.substring(0, DetectionStoreLogger.TRUNCATE_SIZE_FOR_LONG_NUMBERS - 1) + "…";
        }
        return res;
    }
}
