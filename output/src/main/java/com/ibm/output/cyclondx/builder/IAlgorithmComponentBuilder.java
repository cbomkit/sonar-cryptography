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

import com.ibm.mapper.model.INode;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.component.evidence.Occurrence;

public interface IAlgorithmComponentBuilder {
    @Nonnull
    IAlgorithmComponentBuilder algorithm(@Nullable INode algorithm);

    @Nonnull
    IAlgorithmComponentBuilder parameterSetIdentifier(@Nullable INode parameterSetIdentifier);

    @Nonnull
    IAlgorithmComponentBuilder mode(@Nullable INode modes);

    @Nonnull
    IAlgorithmComponentBuilder primitive(@Nullable INode primitive);

    @Nonnull
    IAlgorithmComponentBuilder padding(@Nullable INode padding);

    @Nonnull
    IAlgorithmComponentBuilder curve(@Nullable INode curve);

    @Nonnull
    IAlgorithmComponentBuilder cryptoFunctions(@Nullable INode... cryptoFunctions);

    @Nonnull
    IAlgorithmComponentBuilder occurrences(@Nullable Occurrence... occurrences);

    @Nonnull
    IAlgorithmComponentBuilder oid(@Nullable INode oid);

    @Nonnull
    IAlgorithmComponentBuilder provider(@Nullable INode provider);

    @Nonnull
    Component build();
}
