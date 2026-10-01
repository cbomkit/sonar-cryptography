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
 * Generates a synthetic corpus of OpenSSL EVP cipher-init call sites for the cxx call-stack heap
 * harness. Each unit is its own {@code .cc} file with a distinct function name so recorded calls
 * grow with corpus size. Every unit's {@code EVP_EncryptInit_ex} call passes a nested function-call
 * argument (e.g. {@code EVP_aes_256_gcm()}), the exact shape that made {@code
 * CxxLanguageTranslation#getMethodParameterTypes} fall through to {@code
 * AstNodeTypeExtension.getType} and {@code createTypeFromCxxType} on a real cxx {@code Type} - the
 * code path that used to leak the whole file's AST into the closure stored on the recorded call.
 */
final class CxxCryptoCorpusGenerator {

    private CxxCryptoCorpusGenerator() {}

    private static final List<String> CIPHERS =
            List.of("EVP_aes_128_gcm", "EVP_aes_192_gcm", "EVP_aes_256_gcm", "EVP_aes_256_cbc");

    @Nonnull
    static List<Path> generate(@Nonnull Path root, int units) throws IOException {
        Path pkg = Files.createDirectories(root.resolve("perf"));
        List<Path> files = new ArrayList<>(units);
        for (int i = 0; i < units; i++) {
            String cipher = CIPHERS.get(i % CIPHERS.size());
            Path unit = pkg.resolve("Unit" + i + ".cc");
            Files.writeString(unit, unitSource(i, cipher));
            files.add(unit);
        }
        return files;
    }

    @Nonnull
    private static String unitSource(int i, @Nonnull String cipher) {
        return "#include <openssl/evp.h>\n\n"
                + "void encrypt_unit"
                + i
                + "(EVP_CIPHER_CTX* ctx, unsigned char* key, unsigned char* iv) {\n"
                + "    EVP_EncryptInit_ex(ctx, "
                + cipher
                + "(), NULL, key, iv);\n"
                + "}\n";
    }
}
