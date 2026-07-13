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
package com.ibm.plugin.perf;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CryptoCorpusGeneratorTest {

    @Test
    void generatesTwoFilesPerUnitThatCompile(@TempDir Path tmp) throws Exception {
        List<Path> files = CryptoCorpusGenerator.generate(tmp, 3);

        assertThat(files).hasSize(6);
        assertThat(files).allSatisfy(p -> assertThat(Files.exists(p)).isTrue());

        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        List<String> args = new ArrayList<>(List.of("-d", tmp.resolve("out").toString()));
        files.forEach(p -> args.add(p.toAbsolutePath().toString()));
        int rc = compiler.run(null, null, null, args.toArray(new String[0]));

        assertThat(rc).as("generated corpus must compile cleanly").isZero();
    }
}
