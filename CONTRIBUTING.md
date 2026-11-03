# Contributing

The Sonar Cryptography Plugin is an open source project that aims to create 
an easy way to discover the use of cryptography in source code and create CBOM. 
This page describes how you can join the community in this goal.

## Before you start

If you are new to the community? We recommend you do the following before diving into the code:

* Read the [Code of Conduct](https://github.com/cbomkit/sonar-cryptography/blob/main/CODE_OF_CONDUCT.md)
* Familiarize yourself with the community (via [GitHub](https://github.com/cbomkit/sonar-cryptography/discussions) etc.)

## Choose an issue to work on
The Sonar Cryptography Plugin uses the following labels to help non-maintainers find issues best suited to their interest and experience level:

* [good first issue](https://github.com/cbomkit/sonar-cryptography/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) - these issues are typically the simplest available to work on, ideal for newcomers. They should already be fully scoped, with a clear approach outlined in the descriptions.
* [help wanted](https://github.com/cbomkit/sonar-cryptography/issues?q=is%3Aopen+is%3Aissue+label%3A%22help+wanted%22) - these issues are generally more complex than good first issues. They typically cover work that core maintainers don't currently have capacity to implement and may require more investigation/discussion. These are a great option for experienced contributors looking for something a bit more challenging.

## Code Style

Check if all java files are well formated and license headers are in place.
```shell
mvn spotless:check
```
Applies format and license headers to files.
```shell
mvn spotless:apply
```
Spotless Maven Documentation: https://github.com/diffplug/spotless/blob/main/plugin-maven/README.md

Check for coding style
```shell
mvn checkstyle::check
```

## Build

Execute the following command in the project directory:
```shell
mvn clean package
```
This builds the default `plugin` variant. The `.jar` file is stored in
`distribution/plugin/target` and also copied to `.SonarQube/plugins`.

The other variants are selected with a Maven profile (see the
[README](README.md#build)):
```shell
# Plugin with Go support (bundles SSALv1-licensed sonar-go: private use only)
mvn clean package -Pwith-go

# Library for embedding in another tool (bundles the LGPL-3.0 analyzers)
mvn clean package -Plib
```
Naming a profile turns the default `plugin` profile off. Do not combine `plugin`
and `with-go`. The usual commands work unchanged for the default variant, for
example `mvn test`, `mvn test -pl java` and `mvn spotless:apply`. For Go work, add
the profile: `mvn test -pl go -am -Pwith-go`.

### Profiles in the IDE

The `go` module is part of the build only with the `with-go` profile, and
`distribution/library` only with `lib`. To work on them in an IDE, enable the
profile there:

- **IntelliJ IDEA:** in the Maven tool window, open *Profiles*, tick `with-go`
  (or `lib`) and reload the Maven projects.
- **VS Code (Language Support for Java):** the Maven import has no profile
  setting. Use a Maven settings file that activates the profile:
  ```xml
  <settings>
    <activeProfiles>
      <activeProfile>with-go</activeProfile>
    </activeProfiles>
  </settings>
  ```
  Point `java.configuration.maven.userSettings` at it, then run
  *Java: Clean Java Language Server Workspace*. This file replaces your
  `~/.m2/settings.xml` for the import, so copy any mirrors or servers you need
  into it, and keep it out of the repository.

## Run the Plugin with SonarQube

```shell
# starts a postgres database and a sonarqube instance 
docker-compose up
```

### Configure SonarQube

For the initial configuration and setup, 
take a look at the [official SonarQube documentation](https://docs.sonarqube.org/latest/try-out-sonarqube/).

