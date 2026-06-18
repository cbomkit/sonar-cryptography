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
package com.ibm.mapper.model;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.ascon.Ascon128;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.padding.PKCS5;
import com.ibm.mapper.utils.DetectionLocation;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class AlgorithmDeepCopyTest {

    private static final DetectionLocation DETECTION_LOCATION =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

    @ParameterizedTest(name = "{0}")
    @MethodSource("directAlgorithmSubclasses")
    void directAlgorithmSubclassesMustDeepCopyToTheirConcreteType(
            Class<? extends Algorithm> algorithmClass) {
        Algorithm algorithm = instantiate(algorithmClass);

        INode copy = algorithm.deepCopy();

        assertThat(copy.getClass())
                .as("%s.deepCopy() must preserve concrete type", algorithmClass.getName())
                .isEqualTo(algorithmClass);
    }

    @Test
    void deepCopyPreservesDirectAlgorithmSubclass() {
        AES aes =
                new AES(
                        128,
                        new CBC(DETECTION_LOCATION),
                        new PKCS5(DETECTION_LOCATION),
                        DETECTION_LOCATION);

        INode copy = aes.deepCopy();

        assertThat(copy).isInstanceOf(AES.class).isNotSameAs(aes);
        assertThat(copy.hasChildOfType(KeyLength.class)).isPresent();
        assertThat(copy.hasChildOfType(KeyLength.class).get())
                .isNotSameAs(aes.hasChildOfType(KeyLength.class).get());

        // Verify metadata is preserved
        AES aesCopy = (AES) copy;
        assertThat(aesCopy.getName()).isEqualTo(aes.getName());
        assertThat(aesCopy.getKind()).isEqualTo(aes.getKind());
        assertThat(aesCopy.getDetectionContext()).isEqualTo(aes.getDetectionContext());
        assertThat(aesCopy.getOrigin()).isEqualTo(aes.getOrigin());
    }

    @Test
    void deepCopyPreservesExistingSpecializedSubclass() {
        RSA rsa = new RSA(2048, DETECTION_LOCATION);

        INode copy = rsa.deepCopy();

        assertThat(copy).isInstanceOf(RSA.class).isNotSameAs(rsa);
        assertThat(copy.hasChildOfType(KeyLength.class)).isPresent();
        // Verify the recursive child.deepCopy() loop ran — child must be a distinct object
        assertThat(copy.hasChildOfType(KeyLength.class).get())
                .isNotSameAs(rsa.hasChildOfType(KeyLength.class).get());

        // Verify metadata is preserved (especially origin, which the old custom path could drop)
        RSA rsaCopy = (RSA) copy;
        assertThat(rsaCopy.getName()).isEqualTo(rsa.getName());
        assertThat(rsaCopy.getKind()).isEqualTo(rsa.getKind());
        assertThat(rsaCopy.getDetectionContext()).isEqualTo(rsa.getDetectionContext());
        assertThat(rsaCopy.getOrigin()).isEqualTo(rsa.getOrigin());
    }

    @Test
    void deepCopyPreservesIndirectAlgorithmSubclass() {
        Ascon128 ascon128 = new Ascon128(DETECTION_LOCATION);

        INode copy = ascon128.deepCopy();

        assertThat(copy).isInstanceOf(Ascon128.class).isNotSameAs(ascon128);
        assertThat(copy.hasChildOfType(TagLength.class)).isPresent();
        // Verify the recursive child.deepCopy() loop ran — child must be a distinct object
        assertThat(copy.hasChildOfType(TagLength.class).get())
                .isNotSameAs(ascon128.hasChildOfType(TagLength.class).get());

        // Verify metadata is preserved
        Ascon128 asconCopy = (Ascon128) copy;
        assertThat(asconCopy.getName()).isEqualTo(ascon128.getName());
        assertThat(asconCopy.getKind()).isEqualTo(ascon128.getKind());
        assertThat(asconCopy.getDetectionContext()).isEqualTo(ascon128.getDetectionContext());
        assertThat(asconCopy.getOrigin()).isEqualTo(ascon128.getOrigin());
    }

    private static Stream<Class<? extends Algorithm>> directAlgorithmSubclasses()
            throws IOException, URISyntaxException, ClassNotFoundException {
        return algorithmClassesIn("com.ibm.mapper.model.algorithms")
                .filter(algorithmClass -> algorithmClass.getSuperclass().equals(Algorithm.class))
                .filter(algorithmClass -> !Modifier.isAbstract(algorithmClass.getModifiers()))
                .sorted(Comparator.comparing(Class::getName));
    }

    private static Stream<Class<? extends Algorithm>> algorithmClassesIn(
            @Nonnull String packageName)
            throws IOException, URISyntaxException, ClassNotFoundException {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        String packagePath = packageName.replace('.', '/');
        Enumeration<URL> resources = classLoader.getResources(packagePath);

        Stream.Builder<Class<? extends Algorithm>> classes = Stream.builder();
        while (resources.hasMoreElements()) {
            URL resource = resources.nextElement();
            if ("file".equals(resource.getProtocol())) {
                try (Stream<Path> paths = Files.walk(Path.of(resource.toURI()))) {
                    for (Path classFile :
                            paths.filter(path -> path.toString().endsWith(".class")).toList()) {
                        String className =
                                toClassName(packageName, Path.of(resource.toURI()), classFile);
                        Class<?> loadedClass = Class.forName(className);
                        if (Algorithm.class.isAssignableFrom(loadedClass)
                                && !loadedClass.getName().contains("$")) {
                            classes.add(loadedClass.asSubclass(Algorithm.class));
                        }
                    }
                }
            }
        }
        return classes.build();
    }

    private static String toClassName(
            @Nonnull String packageName, @Nonnull Path packageRoot, @Nonnull Path classFile) {
        String relativeClassName =
                packageRoot
                        .relativize(classFile)
                        .toString()
                        .replace('\\', '.')
                        .replace('/', '.')
                        .replaceAll("\\.class$", "");
        return packageName + "." + relativeClassName;
    }

    private static Algorithm instantiate(@Nonnull Class<? extends Algorithm> algorithmClass) {
        return Arrays.stream(algorithmClass.getDeclaredConstructors())
                .filter(constructor -> !isCopyConstructor(algorithmClass, constructor))
                .sorted(Comparator.comparingInt(Constructor::getParameterCount))
                .map(constructor -> instantiate(algorithmClass, constructor))
                .flatMap(Optional::stream)
                .findFirst()
                .orElseThrow(
                        () ->
                                new AssertionError(
                                        "No supported constructor found for "
                                                + algorithmClass.getName()));
    }

    private static boolean isCopyConstructor(
            @Nonnull Class<? extends Algorithm> algorithmClass,
            @Nonnull Constructor<?> constructor) {
        return constructor.getParameterCount() == 1
                && constructor.getParameterTypes()[0].equals(algorithmClass);
    }

    private static Optional<Algorithm> instantiate(
            @Nonnull Class<? extends Algorithm> algorithmClass,
            @Nonnull Constructor<?> constructor) {
        Optional<Object[]> arguments = argumentsFor(constructor.getParameterTypes());
        if (arguments.isEmpty()) {
            return Optional.empty();
        }
        try {
            constructor.setAccessible(true);
            return Optional.of((Algorithm) constructor.newInstance(arguments.get()));
        } catch (InstantiationException
                | IllegalAccessException
                | InvocationTargetException
                | IllegalArgumentException exception) {
            throw new AssertionError(
                    "Could not instantiate " + algorithmClass.getName() + " using " + constructor,
                    exception);
        }
    }

    private static Optional<Object[]> argumentsFor(@Nonnull Class<?>[] parameterTypes) {
        Object[] arguments = new Object[parameterTypes.length];
        for (int i = 0; i < parameterTypes.length; i++) {
            Optional<Object> argument = argumentFor(parameterTypes[i]);
            if (argument.isEmpty()) {
                return Optional.empty();
            }
            arguments[i] = argument.get();
        }
        return Optional.of(arguments);
    }

    private static Optional<Object> argumentFor(@Nonnull Class<?> parameterType) {
        if (parameterType.equals(DetectionLocation.class)) {
            return Optional.of(DETECTION_LOCATION);
        } else if (parameterType.equals(int.class) || parameterType.equals(Integer.class)) {
            return Optional.of(128);
        } else if (parameterType.equals(String.class)) {
            return Optional.of("test");
        } else if (parameterType.equals(Class.class)) {
            return Optional.of(IPrimitive.class);
        } else if (parameterType.equals(MessageDigest.class)) {
            return Optional.of(new SHA2(256, DETECTION_LOCATION));
        }
        return Optional.empty();
    }
}
