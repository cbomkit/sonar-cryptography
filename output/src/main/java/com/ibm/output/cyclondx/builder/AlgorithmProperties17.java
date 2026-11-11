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

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import org.cyclonedx.model.component.crypto.AlgorithmProperties;
import org.cyclonedx.model.component.crypto.enums.Primitive;

/**
 * Algorithm properties that can serialize the CycloneDX 1.7 {@code key-wrap} primitive.
 *
 * <p>cyclonedx-core-java 13.2.0 validates against the 1.7 schema but its {@link Primitive}
 * enumeration has no key-wrap constant yet. For key wrapping algorithms {@link #getPrimitive()}
 * keeps returning {@link Primitive#OTHER}, while the serialized {@code primitive} is {@code
 * key-wrap}. This class can be dropped once the library provides the constant.
 */
public class AlgorithmProperties17 extends AlgorithmProperties {
    private static final String KEY_WRAP = "key-wrap";

    private boolean keyWrap;

    public void setKeyWrap(boolean keyWrap) {
        this.keyWrap = keyWrap;
    }

    @JsonIgnore
    @Override
    public Primitive getPrimitive() {
        return super.getPrimitive();
    }

    @JsonGetter("primitive")
    public String getSerializedPrimitive() {
        if (keyWrap) {
            return KEY_WRAP;
        }
        final Primitive primitive = super.getPrimitive();
        return primitive == null ? null : primitive.getName();
    }
}
