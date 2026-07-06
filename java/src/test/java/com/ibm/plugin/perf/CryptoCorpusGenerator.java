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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Generates a synthetic corpus of cross-file crypto wrapper/caller unit pairs for the call-stack
 * heap harness. Each unit is a {@code WrapperK} whose factory method takes the algorithm as a
 * parameter (forcing a cross-file method hook) and a {@code CallerK} that invokes it with a string
 * literal and a field constant (both detachable recorded calls). Distinct class names per unit keep
 * call sites distinct so the recorded-call set grows with corpus size, approximating a large
 * project without checking one in. Uses only JDK JCA APIs so the corpus compiles and resolves.
 */
final class CryptoCorpusGenerator {

    private CryptoCorpusGenerator() {}

    /** A JCA factory rotated across units so multiple detection rules fire. */
    private record Api(@Nonnull String call, @Nonnull String algo) {}

    private static final List<Api> APIS =
            List.of(
                    new Api("javax.crypto.Cipher.getInstance(algo)", "AES"),
                    new Api("javax.crypto.KeyGenerator.getInstance(algo)", "AES"),
                    new Api("java.security.MessageDigest.getInstance(algo)", "SHA-256"));

    @Nonnull
    static List<Path> generate(@Nonnull Path root, int units) throws IOException {
        Path pkg = Files.createDirectories(root.resolve("perf"));
        List<Path> files = new ArrayList<>();
        for (int i = 0; i < units; i++) {
            Api api = APIS.get(i % APIS.size());

            Path wrapper = pkg.resolve("Wrapper" + i + ".java");
            Files.writeString(wrapper, wrapperSource(i, api));
            files.add(wrapper);

            Path caller = pkg.resolve("Caller" + i + ".java");
            Files.writeString(caller, callerSource(i, api));
            files.add(caller);
        }
        return files;
    }

    @Nonnull
    private static String wrapperSource(int i, @Nonnull Api api) {
        return "package perf;\n\n"
                + "public class Wrapper"
                + i
                + " {\n"
                + "    public Object make(String algo) throws Exception {\n"
                + "        return "
                + api.call()
                + ";\n"
                + "    }\n"
                + "}\n";
    }

    @Nonnull
    private static String callerSource(int i, @Nonnull Api api) {
        return "package perf;\n\n"
                + "public class Caller"
                + i
                + " {\n"
                + "    static final String ALGO = \""
                + api.algo()
                + "\";\n"
                + "    void run() throws Exception {\n"
                + "        new Wrapper"
                + i
                + "().make(\""
                + api.algo()
                + "\");\n"
                + "        new Wrapper"
                + i
                + "().make(ALGO);\n"
                + "    }\n"
                + "}\n";
    }
}
