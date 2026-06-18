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
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.MessageDigest;
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
 *   <li>See 4.3.3 of
 *       https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_V-2-1_pdf.pdf?__blob=publicationFile&v=1
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>Key Derivation Function for Session Keys
 * </ul>
 */
public final class KDFSession extends Algorithm implements KeyDerivationFunction {
    private static final String NAME = "KDF Session";

    public KDFSession(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, KeyDerivationFunction.class, detectionLocation);
    }

    public KDFSession(@Nonnull MessageDigest messageDigest) {
        this(messageDigest.getDetectionContext());
        this.put(messageDigest);
    }

    private KDFSession(@Nonnull KDFSession kDFSession) {
        super(kDFSession);
    }

    @Nonnull
    @Override
    protected KDFSession shallowCopy() {
        return new KDFSession(this);
    }
}
