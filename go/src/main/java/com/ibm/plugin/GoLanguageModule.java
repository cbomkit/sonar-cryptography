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
import com.ibm.output.ILanguageModule;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Go support. It uses sonar-go internals that SonarQube does not export to other plugins, so this
 * module is only packaged into a plugin that bundles sonar-go itself. Where it is packaged, the
 * analyzer is therefore always available.
 */
public final class GoLanguageModule implements ILanguageModule {

    @Nonnull
    @Override
    public String name() {
        return "Go";
    }

    @Override
    public int order() {
        return 30;
    }

    @Override
    public boolean isAvailable() {
        return true;
    }

    @Nonnull
    @Override
    public List<Object> serverExtensions() {
        return List.of(GoScannerRuleDefinition.class);
    }

    @Nonnull
    @Override
    public List<Object> scannerExtensions() {
        return List.of(CryptoGoSensor.class); // Custom sensor (sonar-go has no CheckRegistrar API)
    }

    @Nonnull
    @Override
    public List<INode> detectedNodes() {
        return GoAggregator.getDetectedNodes();
    }

    @Override
    public void reset() {
        GoAggregator.reset();
    }
}
