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
package com.ibm.plugin.rules.detection.auth;

import java.io.File;
import java.util.List;

public class AuthInterfaceJars {
    // Pinned API jars handed to the analyzer so it can resolve the auth-interface types referenced
    // in the detection test files (io.jsonwebtoken.Jwts, jakarta.servlet.http.HttpServletRequest).
    // Mirrors the BouncyCastleJars convention: resolution is deterministic and self-contained,
    // independent of whatever Maven happens to place on the test runtime classpath.
    public static List<File> jars =
            List.of(
                    new File("src/test/resources/test-jars/jjwt-api-0.12.6.jar"),
                    new File("src/test/resources/test-jars/jakarta.servlet-api-6.0.0.jar"),
                    new File("src/test/resources/test-jars/nimbus-jose-jwt-9.40.jar"),
                    new File("src/test/resources/test-jars/java-jwt-4.4.0.jar"),
                    new File("src/test/resources/test-jars/spring-security-oauth2-jose-6.3.3.jar"),
                    new File(
                            "src/test/resources/test-jars/spring-security-oauth2-resource-server-6.3.3.jar"),
                    new File("src/test/resources/test-jars/oauth2-oidc-sdk-11.13.jar"));
}
