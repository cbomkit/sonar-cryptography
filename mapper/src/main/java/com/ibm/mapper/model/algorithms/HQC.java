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
package com.ibm.mapper.model.algorithms;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

/**
 *
 *
 * <h2>{@value #NAME}</h2>
 *
 * <p>
 *
 * <h3>Specification</h3>
 *
 * <ul>
 *   <li>https://pqc-hqc.org/doc/hqc-specification_2023-04-30.pdf
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>Hamming Quasi-Cyclic
 * </ul>
 */
public final class HQC extends Algorithm implements KeyEncapsulationMechanism, PublicKeyEncryption {

    private static final String NAME = "HQC";

    /** Returns a more specific name "HQC.KEM" or "HQC.PKE" length */
    @Override
    @Nonnull
    public String asString() {
        StringBuilder builtName = new StringBuilder(this.name);

        if (this.getKind() == KeyEncapsulationMechanism.class) {
            builtName.append(".KEM");
        } else if (this.getKind() == PublicKeyEncryption.class) {
            builtName.append(".PKE");
        }

        return builtName.toString();
    }

    public HQC(
            @Nonnull final Class<? extends IPrimitive> asKind,
            @Nonnull DetectionLocation detectionLocation) {
        super(NAME, asKind, detectionLocation);
    }

    private HQC(@Nonnull HQC hQC) {
        super(hQC);
    }

    @Nonnull
    @Override
    protected HQC shallowCopy() {
        return new HQC(this);
    }
}
