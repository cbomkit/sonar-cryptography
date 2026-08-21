# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **Sonar Cryptography Plugin (CBOMkit-hyperion)** - a SonarQube plugin that detects cryptographic assets in source code and generates Cryptographic Bill of Materials (CBOM) in CycloneDX format. Part of the [CBOMKit](https://github.com/cbomkit) toolset.

**Supported languages/libraries:**
- Java: JCA (100%), BouncyCastle light-weight API (100%)
- Python: pyca/cryptography (100%)
- Go: `crypto` standard library (100%, except `crypto/x509`), `golang.org/x/crypto` (partial: `hkdf`, `pbkdf2`, `sha3`)

## Build Commands

```bash
# Build with tests
mvn clean package

# Build without tests
mvn clean package -DskipTests

# Build specific module
mvn clean package -pl java

# Format code (Google Java Format, AOSP style)
mvn spotless:apply

# Check formatting
mvn spotless:check

# Check code style
mvn checkstyle:check
```

**Cipher-suite data:** `mapper/ciphersuites.json` and the generated
`mapper/src/main/java/.../ssl/json/JsonCipherSuites.java` are checked into git. The build does
not touch them. To refresh them from ciphersuite.info, run `mapper/download-cipher-suites.sh`
and then `mvn -pl mapper spotless:apply`, or trigger the `Update cipher suites` workflow, which
opens a pull request with the change.

## Testing

```bash
# Run all tests
mvn test

# Run tests for specific module
mvn test -pl java
mvn test -pl python
mvn test -pl go
mvn test -pl mapper
mvn test -pl engine

# Run specific test class
mvn test -Dtest=SimpleGuidelineTest

# Run specific test method
mvn test -Dtest=SimpleGuidelineTest#testBasicAssertion
```

**Testing Framework:** JUnit 5 + AssertJ + SonarQube Test Fixtures

**Detection rule tests:**
- Extend the `TestBase` of the language module you're testing (`java`, `python` and `go` each have their own at `<module>/src/test/java/com/ibm/plugin/TestBase.java`)
- Use the SonarQube verifier for that language: `CheckVerifier` (Java), `PythonCheckVerifier` (Python), `GoVerifier` (Go)
- Test files (actual code to analyze) go in `src/test/files/`, not `src/test/java/`
- Implement `asserts()` method to verify detection store values and translated nodes

## Architecture

Multi-module Maven project (Java 17):

```
sonar-cryptography-plugin/    # Main SonarQube plugin entry point
├── CryptographyPlugin.java   # Plugin registration
├── OutputFileJob.java        # CBOM output handler
engine/                       # Core detection engine
├── detection/                # DetectionStore, Finding classes
├── rule/                     # IDetectionRule interface
java/                         # Java language support (JCA, BouncyCastle)
├── rules/detection/          # Java detection rules
python/                       # Python language support (pyca/cryptography)
go/                           # Go language support (crypto stdlib, golang.org/x/crypto)
├── rules/detection/gocrypto/ # Go detection rules
mapper/                       # Translation layer to CBOM model
├── model/                    # Core data model (Algorithm, Key, Protocol, etc.)
├── ITranslator.java          # Main translation interface
enricher/                     # Adds algorithm details to findings
output/                       # CBOM/CycloneDX generation
common/                       # Shared utilities
rules/                        # Shared rule definitions
```

**Data flow:** Source code → Language module (AST) → Engine (detection) → Mapper (translation) → Enricher → Output (CBOM)

## Code Style

- **Formatting:** Google Java Format (AOSP style) via Spotless - runs on `mvn package`
- **License:** Apache 2.0 header required in all Java files (applied by Spotless)
- **Checkstyle rules:** No unused imports, camelCase lambda params, max 5 boolean operators, private utility constructors, @Override required

## Running with SonarQube

```bash
docker-compose up  # Starts PostgreSQL + SonarQube
```

Plugin JAR is built to `sonar-cryptography-plugin/target/` and copied to `.SonarQube/plugins/`.

## Key Documentation

- `docs/LANGUAGE_SUPPORT.md` - Extending for new languages/libraries
- `docs/DETECTION_RULE_STRUCTURE.md` - Writing detection rules
- `docs/TROUBLESHOOTING.md` - Testing configuration guide
- `docs/PERFORMANCE_TESTING.md` - Runtime/heap measurement, including full Keycloak scans
- `README.md` (Build section) - Adding packages to `sonar-go-to-slang` when Go type resolution fails