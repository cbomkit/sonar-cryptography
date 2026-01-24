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
package com.ibm.plugin;

import com.ibm.mapper.model.INode;
import com.ibm.output.IOutputFile;
import com.ibm.output.IOutputFileFactory;
import com.ibm.output.statistics.IStatistics;
import com.ibm.output.statistics.ScanStatistics;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class ScannerManager {
    private final IOutputFileFactory outputFileFactory;

    public ScannerManager(@Nullable IOutputFileFactory outputFileFactory) {
        this.outputFileFactory = outputFileFactory;
    }

    @Nonnull
    public IOutputFile getOutputFile() {
        return Optional.ofNullable(this.outputFileFactory)
                .orElse(IOutputFileFactory.DEFAULT)
                .createOutputFormat(getAggregatedNodes());
    }

    @Nonnull
    public IStatistics getStatistics() {
        return new ScanStatistics(
                () -> getAggregatedNodes().size(), // numberOfDetectedAssetsSupplier
                () ->
                        getAggregatedNodes().stream() // numberOfAssetsPerTypeSupplier
                                .collect(
                                        Collectors.groupingBy(
                                                INode::getKind, Collectors.counting())));
    }

    public boolean hasResults() {
        return !this.getAggregatedNodes().isEmpty();
    }

    @Nonnull
    private List<INode> getAggregatedNodes() {
        List<INode> nodes = new ArrayList<>();
        nodes.addAll(JavaAggregator.getDetectedNodes());
        nodes.addAll(PythonAggregator.getDetectedNodes());
        nodes.addAll(GoAggregator.getDetectedNodes());
        return nodes;
    }

    public void reset() {
        JavaAggregator.reset();
        PythonAggregator.reset();
        GoAggregator.reset();
    }
}
