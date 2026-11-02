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

import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.api.config.PropertyDefinition;
import org.sonar.api.config.PropertyDefinition.ConfigScope;

public final class Configuration {

    private Configuration() {}

    public static @Nonnull List<PropertyDefinition> getPropertyDefinitions() {
        return List.of(
                PropertyDefinition.builder(Constants.CBOM_OUTPUT_NAME)
                        .onConfigScopes(ConfigScope.PROJECT)
                        .subCategory(Constants.SUB_CATEGORY_GENERAL)
                        .name("CBOM filename")
                        .description("Filename for the generated CBOM")
                        .defaultValue(Constants.CBOM_OUTPUT_NAME_DEFAULT)
                        .build());
    }
}
