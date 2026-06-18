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
import com.ibm.mapper.model.MaskGenerationFunction;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

public final class MGF1 extends Algorithm implements MaskGenerationFunction {

    public MGF1(@Nonnull DetectionLocation detectionLocation) {
        super("MGF1", MaskGenerationFunction.class, detectionLocation);
        this.put(new Oid("1.2.840.113549.1.1.8", detectionLocation));
    }

    public MGF1(@Nonnull MessageDigest messageDigest) {
        this(messageDigest.getDetectionContext());
        this.put(messageDigest);
    }

    private MGF1(@Nonnull MGF1 mGF1) {
        super(mGF1);
    }

    @Nonnull
    @Override
    protected MGF1 shallowCopy() {
        return new MGF1(this);
    }
}
