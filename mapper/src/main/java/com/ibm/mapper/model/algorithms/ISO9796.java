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
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

public class ISO9796 extends Algorithm implements Signature, ProbabilisticSignatureScheme {
    private static final String NAME = "ISO 9796";

    /** Appends "-PSS" to the name if it is used as a ProbabilisticSignatureScheme */
    @Override
    @Nonnull
    public String asString() {
        if (this.getKind() == ProbabilisticSignatureScheme.class) {
            return this.getName() + "-PSS";
        } else {
            return this.getName();
        }
    }

    public ISO9796(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, Signature.class, detectionLocation);
    }

    public ISO9796(
            @Nonnull final Class<? extends IPrimitive> asKind,
            @Nonnull DetectionLocation detectionLocation) {
        super(NAME, asKind, detectionLocation);
    }

    public ISO9796(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull ISO9796 iso) {
        super(iso, asKind);
    }

    private ISO9796(@Nonnull ISO9796 iSO9796) {
        super(iSO9796);
    }

    @Nonnull
    @Override
    protected ISO9796 shallowCopy() {
        return new ISO9796(this);
    }
}
