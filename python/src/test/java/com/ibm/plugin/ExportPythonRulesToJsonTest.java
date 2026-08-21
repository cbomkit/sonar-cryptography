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

import com.ibm.engine.rule.RuleSets;
import com.ibm.engine.serializer.ExportRules;
import com.ibm.plugin.rules.detection.PythonDetectionRules;
import java.io.FileWriter;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/* This class is not really a test, but is used to export all Python rules to a JSON file */
class ExportPythonRulesToJsonTest extends ExportRules {
    private static final Logger LOGGER = LoggerFactory.getLogger(ExportPythonRulesToJsonTest.class);

    @Test
    void test() {
        try (FileWriter fileWriter = new FileWriter("target/rules.json")) {
            exportToJSON(RuleSets.rulesOf(PythonDetectionRules.class), fileWriter);
        } catch (IOException e) {
            LOGGER.warn("Error exporting Java rules to JSON file: " + e.getMessage());
        }
    }
}
