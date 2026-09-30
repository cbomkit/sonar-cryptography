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
package com.ibm.mapper.model;

import static com.ibm.mapper.model.ModelNodes.TEST;
import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.mode.GMAC;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * An algorithm as another kind is an algorithm of the same class, e.g. an AES block cipher used as
 * a MAC is still an AES: the class gives its composed name, how the enrichers complete it and how
 * the output reports it. Every concrete algorithm class of the model is checked.
 */
class AlgorithmAsKindTest {

    @Test
    void everyAlgorithmClassIsTheSameAlgorithmAsAnotherKind()
            throws IOException, URISyntaxException {
        final List<String> failures = new ArrayList<>();
        for (Class<? extends INode> nodeClass : ModelNodes.concreteNodeClasses()) {
            if (ModelNodes.build(nodeClass) instanceof Algorithm algorithm) {
                failures.addAll(differencesAsOtherKind(algorithm));
            }
        }
        assertThat(failures).isEmpty();
    }

    @Test
    void aCipherAsAMacInGmacModeIsNamedAfterItsKeyLengthAndMode() {
        final Algorithm gmac = new AES(128, new GMAC(TEST), TEST).asKind(Mac.class);

        assertThat(gmac).isInstanceOf(AES.class);
        assertThat(gmac.getKind()).isEqualTo(Mac.class);
        assertThat(gmac.asString()).isEqualTo("AES-128-GMAC");
    }

    /**
     * What differs between the algorithm and the algorithm as another kind, other than its kind.
     */
    @Nonnull
    private static List<String> differencesAsOtherKind(@Nonnull Algorithm algorithm) {
        final String name = algorithm.getClass().getName();
        final Class<? extends IPrimitive> otherKind =
                algorithm.getKind().equals(Mac.class) ? BlockCipher.class : Mac.class;
        final Algorithm asOtherKind = algorithm.asKind(otherKind);
        final List<String> differences = new ArrayList<>();
        if (asOtherKind.getClass() != algorithm.getClass()) {
            differences.add(name + ": as another kind is a " + asOtherKind.getClass().getName());
            return differences;
        }
        if (!asOtherKind.getKind().equals(otherKind)) {
            differences.add(name + ": kind " + asOtherKind.getKind() + " instead of " + otherKind);
        }
        if (!asOtherKind.getName().equals(algorithm.getName())) {
            differences.add(
                    name
                            + ": named "
                            + asOtherKind.getName()
                            + " instead of "
                            + algorithm.getName());
        }
        if (asOtherKind.getDetectionContext() != algorithm.getDetectionContext()) {
            differences.add(name + ": another detection location");
        }
        if (asOtherKind.getOrigin() != algorithm.getOrigin()) {
            differences.add(
                    name
                            + ": origin "
                            + asOtherKind.getOrigin()
                            + " instead of "
                            + algorithm.getOrigin());
        }
        if (!asOtherKind.getChildren().equals(algorithm.getChildren())) {
            differences.add(name + ": other children");
        }
        return differences;
    }
}
