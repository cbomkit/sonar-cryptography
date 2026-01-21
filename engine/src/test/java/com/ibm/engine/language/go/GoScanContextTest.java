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
package com.ibm.engine.language.go;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import java.net.URI;
import org.junit.jupiter.api.Test;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.checks.CheckContext;
import org.sonar.plugins.go.api.checks.GoCheck;

class GoScanContextTest {

    @Test
    void shouldReturnFilePath() {
        // Arrange
        CheckContext mockContext = mock(CheckContext.class);
        InputFile mockInputFile = mock(InputFile.class);
        when(mockContext.inputFile()).thenReturn(mockInputFile);
        when(mockInputFile.uri()).thenReturn(URI.create("file:///path/to/file.go"));

        GoScanContext scanContext = new GoScanContext(mockContext);

        // Act
        String filePath = scanContext.getFilePath();

        // Assert
        assertThat(filePath).isEqualTo("/path/to/file.go");
    }

    @Test
    void shouldReturnInputFile() {
        // Arrange
        CheckContext mockContext = mock(CheckContext.class);
        InputFile mockInputFile = mock(InputFile.class);
        when(mockContext.inputFile()).thenReturn(mockInputFile);

        GoScanContext scanContext = new GoScanContext(mockContext);

        // Act & Assert
        assertThat(scanContext.getInputFile()).isSameAs(mockInputFile);
    }

    @Test
    void shouldReportIssue() {
        // Arrange
        CheckContext mockContext = mock(CheckContext.class);
        Tree mockTree = mock(Tree.class);
        GoCheck mockRule = mock(GoCheck.class);

        GoScanContext scanContext = new GoScanContext(mockContext);

        // Act
        scanContext.reportIssue(mockRule, mockTree, "Test message");

        // Assert - Go API doesn't use the rule parameter
        verify(mockContext).reportIssue(mockTree, "Test message");
    }
}
