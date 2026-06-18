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
import com.ibm.mapper.model.KeyWrap;
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
 *   <li>https://datatracker.ietf.org/doc/html/rfc3211#section-2.3.1
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 * </ul>
 */
public class RFC3211Wrap extends Algorithm implements KeyWrap {

    private static final String NAME = "RFC 3211";

    public RFC3211Wrap(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, KeyWrap.class, detectionLocation);
    }

    private RFC3211Wrap(@Nonnull RFC3211Wrap rFC3211Wrap) {
        super(rFC3211Wrap);
    }

    @Nonnull
    @Override
    protected RFC3211Wrap shallowCopy() {
        return new RFC3211Wrap(this);
    }
}
