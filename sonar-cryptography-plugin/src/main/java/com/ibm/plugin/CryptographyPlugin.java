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

import com.ibm.output.ILanguageModule;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.Plugin;
import org.sonar.api.SonarProduct;
import org.sonar.api.SonarRuntime;

public class CryptographyPlugin implements Plugin {

    @SuppressWarnings({"java:S1874"})
    private static final Logger LOGGER = LoggerFactory.getLogger(CryptographyPlugin.class);

    @Override
    public void define(Context context) {
        SonarRuntime runtime = context.getRuntime();
        SonarProduct product = runtime.getProduct();

        LOGGER.info("Sonar Cryptography initialized in context (" + product + ")");

        context.addExtensions(Configuration.getPropertyDefinitions()); // add configuration

        final List<ILanguageModule> modules = LanguageModules.all();
        // Rule definitions only run on the server, where all required analyzers are installed.
        modules.forEach(module -> context.addExtensions(module.serverExtensions()));
        // Scanner-side extensions that use an analyzer's API are only registered when that
        // analyzer is loaded: scanners load analyzers per detected language (see Analyzers).
        for (ILanguageModule module : modules) {
            if (module.isAvailable()) {
                context.addExtensions(module.scannerExtensions());
            } else {
                LOGGER.info(
                        "The {} analyzer is not loaded: {} cryptography detection is disabled",
                        module.name(),
                        module.name());
            }
        }
        context.addExtension(OutputFileJob.class);
    }
}
