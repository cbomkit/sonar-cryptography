/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
package com.ibm.engine.language.cxx;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

class CxxScanContextTest {

    // Regression test: sonar-cxx's own sensor (CxxSquidSensor.saveViolations) reads issues back
    // from SquidAstVisitorContext's CheckMessage list, populated only by createLineViolation -
    // never from the separate PreciseIssue list SquidCheck.addIssue populates. Calling addIssue
    // here silently drops every finding: no exception, no log, just zero issues in SonarQube
    // despite the CBOM being generated correctly. reportIssue must go through createLineViolation.
    @Test
    void reportIssueGoesThroughCreateLineViolationNotAddIssue() {
        @SuppressWarnings("unchecked")
        SquidAstVisitorContext<Grammar> visitorContext = mock(SquidAstVisitorContext.class);
        SquidCheck<?> check = mock(SquidCheck.class);
        AstNode node = mock(AstNode.class);

        CxxScanContext scanContext = new CxxScanContext(visitorContext);
        scanContext.reportIssue(check, node, "(BlockCipher) AES-256-GCM");

        verify(visitorContext)
                .createLineViolation(eq(check), eq("(BlockCipher) AES-256-GCM"), eq(node));
        verify(check, never()).addIssue(any(), any());
    }
}
