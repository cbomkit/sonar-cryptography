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

import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

/**
 * The National Institute of Standards and Technology (NIST) proposed DSA for use in their Digital
 * Signature Standard (DSS) in 1991, and adopted it as FIPS 186 in 1994. Five revisions to the
 * initial specification have been released. The newest specification is: FIPS 186-5 from February
 * 2023.
 *
 * <p>For now, DSS points to DSA!
 */
public final class DSS extends DSA {

    public DSS(@Nonnull DetectionLocation detectionLocation) {
        super(detectionLocation);
    }

    private DSS(@Nonnull DSS dSS) {
        super(dSS);
    }

    @Nonnull
    @Override
    protected DSS shallowCopy() {
        return new DSS(this);
    }
}
