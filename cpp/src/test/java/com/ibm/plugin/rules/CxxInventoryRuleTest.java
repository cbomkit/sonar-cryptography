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
package com.ibm.plugin.rules;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.plugin.rules.detection.CxxBaseDetectionRule;
import com.ibm.plugin.translation.CxxTranslationProcess;
import java.lang.reflect.Field;
import java.util.List;
import org.junit.jupiter.api.Test;

class CxxInventoryRuleTest {

    @Test
    void theProductionConstructorWiresUpTheRealDetectionAndReorganizerRules() throws Exception {
        // The no-arg constructor is what the SonarQube plugin actually instantiates via
        // reflection at scan time; the protected overload used by other tests only accepts an
        // explicit rule list, so this constructor is otherwise never exercised. Its two fields
        // are declared protected on CxxBaseDetectionRule (a different package), so reflection is
        // used here to observe them rather than widening their visibility just for this test.
        CxxInventoryRule rule = new CxxInventoryRule();

        Field detectionRulesField = CxxBaseDetectionRule.class.getDeclaredField("detectionRules");
        detectionRulesField.setAccessible(true);
        Field translationProcessField =
                CxxBaseDetectionRule.class.getDeclaredField("cxxTranslationProcess");
        translationProcessField.setAccessible(true);

        assertThat((List<?>) detectionRulesField.get(rule)).isNotEmpty();
        assertThat(translationProcessField.get(rule)).isInstanceOf(CxxTranslationProcess.class);
    }
}
