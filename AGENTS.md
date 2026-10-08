# Repository Guidelines

## Project Structure & Module Organization

This is a Java 17, multi-module Maven project. `sonar-cryptography-plugin/` registers the SonarQube plugin. `java/`, `python/`, `go/`, and `csharp/` implement language detection; `engine/` provides shared detection logic. `mapper/`, `enricher/`, and `output/` turn findings into a cryptographic bill of materials. Shared code lives in `common/` and `rules/`. Each module keeps production code in `src/main/java` and tests in `src/test/java`; language test inputs live under `src/test/files/`. See `docs/` for rule and language-extension guides.

## Build, Test, and Development Commands

- `mvn clean package`: build all modules and run tests, as CI does.
- `mvn test`: run the test suite without packaging.
- `mvn test -pl java`: run one module's tests; replace `java` with another module name.
- `mvn spotless:check`: check Java formatting and license headers.
- `mvn spotless:apply`: format Java files and apply required headers.
- `mvn checkstyle:check`: check Java style rules.
- `docker-compose up`: start the local PostgreSQL and SonarQube services after building the plugin.

## Coding Style & Naming Conventions

Use Spotless's Google Java Format in AOSP style for Java indentation, imports, and annotations. Keep the Apache 2.0 license header on Java files. Follow existing package names in lowercase, Java types in `UpperCamelCase`, and methods and fields in `lowerCamelCase`. Checkstyle runs during Maven's `validate` phase; run formatting and style checks before submitting changes.

## Testing Guidelines

Tests use JUnit 5 and AssertJ. Name test classes `*Test.java` and place them beside the corresponding module's code under `src/test/java`. For detection rules, add representative source fixtures under that module's `src/test/files/` and assert the detected findings. Run `mvn test` for broad changes or `mvn test -pl <module>` for focused changes. No numeric coverage threshold is configured in the parent build.

## Writing C# Detection Rules

Declare a rule's parameters with `withNamedMethodParameter` / `withOptionalNamedMethodParameter` using the real .NET parameter names rather than positionally. A rule that declares any named parameter is matched without an arity constraint, and `CSharpNamedArgumentBinder` resolves the overload by binding each parameter by keyword, then by position, then by unique declared type. That is what lets one rule per method cover every overload, place a value correctly when an overload reorders it, and still refuse to guess.

Write one rule per method, not one per arity: two rules on the same method would both match and the call would be detected twice. Mark a parameter required only if every overload has it, since the rule accepts argument counts between the required count and the declared count. Declare a distinctive type (`"HashAlgorithmName"`, `"RSASignaturePadding"`, `"int"`) wherever one exists, because the type is what places a value when the position varies and what rejects an argument that cannot be it. Every new test should also assert the *absence* of a value that cannot be resolved, via `assertNoChild` or a typed `null` passed to `assertChild`: a guessed parameter is worse than a missing one.

## Commits & Pull Requests

Recent commits commonly use short subjects such as `feat: ...`, `fix: ...`, `ci: ...`, and `chore(deps): ...`; some use plain descriptive subjects. Keep the subject specific and include an issue or PR reference when applicable. In pull requests, describe the behavior changed, affected modules, and commands run; link the relevant issue. Add screenshots only for visible SonarQube interface changes.
