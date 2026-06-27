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
package com.ibm.mapper.mapper.ssl;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class SSLVersionMapper implements IMapper {
    @Nonnull
    @Override
    public Optional<Version> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        Pattern pattern = Pattern.compile("^(?:tls|ssl|dtls)v(\\d+(\\.\\d+)?)");
        Matcher matcher = pattern.matcher(str.toLowerCase());
        if (matcher.find()) {
            String number = matcher.group(1);
            if (number.equals("1")) {
                number = "1.0";
            }
            return Optional.of(new Version(number, detectionLocation));
        }
        return Optional.empty();
    }
}
