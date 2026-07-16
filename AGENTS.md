# Project Overview

`org.apache.sling.auth.form` is an OSGi bundle that implements form-based authentication for Apache Sling. It provides login/logout via an HTML form, maintains authentication state in a signed cookie or HTTP session using a HMAC-based token store, and integrates with JAAS via a pluggable login module. The main handler (`FormAuthenticationHandler`) implements `JakartaAuthenticationHandler`. OSGi component wiring uses `org.osgi.service.component.annotations` (R6/R7). Requires Java 17.

# Core Commands

```bash
# Build and package the OSGi bundle
mvn clean package

# Run unit tests only (fast)
mvn test

# Run a single unit test class
mvn test -Dtest=TokenStoreTest

# Run unit + integration tests (Pax Exam)
mvn verify

# Run integration tests only
mvn failsafe:integration-test failsafe:verify

# Run a single integration test class
mvn -Dit.test=SLING10290IT failsafe:integration-test failsafe:verify

# Build with coverage report (JaCoCo)
mvn verify -Pjacoco-report

# Skip tests during build
mvn package -DskipTests
```

No dev server — this is a deployable OSGi bundle, not a standalone app.

# Project Layout

```
pom.xml                        Maven build descriptor
bnd.bnd                        OSGi bundle manifest instructions
src/
  main/
    java/
      org/apache/sling/auth/form/
        FormReason.java                    Public API enum for auth failure reasons
        package-info.java                  Package-level OSGi versioning annotation
        impl/
          FormAuthenticationHandler.java   Core auth handler (OSGi @Component)
          FormAuthenticationHandlerConfig.java OSGi metatype config interface
          AuthenticationFormServlet.java   Serves the login HTML form
          TokenStore.java                  HMAC token generation/validation
          FormLoginModulePlugin.java       Optional Felix JAAS integration
          jaas/
            FormCredentials.java           JAAS credentials holder
            FormLoginModule.java           JAAS LoginModule
            JaasHelper.java                Helper for optional JAAS wiring
    resources/
      OSGI-INF/l10n/                       Metatype property localization
      org/apache/sling/auth/form/impl/login.html  Default login form template
  test/
    java/
      org/apache/sling/auth/form/
        FormReasonTest.java
        impl/
          FormAuthenticationHandlerTest.java Unit tests (Mockito + OSGi mock)
          TokenStoreTest.java
        it/
          AuthFormTestSupport.java
          AuthFormClientTestSupport.java
          SLING10290IT.java
          SLING10421ValidDomainIT.java
          SLING10421InvalidDomainIT.java
    resources/
      exam.properties                      Pax Exam container config
```

# Development Patterns & Constraints

- **Java 17**, no preview features.
- **OSGi DS annotations only**: use `org.osgi.service.component.annotations` (`@Component`, `@Reference`, `@Activate`, etc.). Do not use Felix SCR annotations.
- **Metatype config** via `@ObjectClassDefinition` + `@AttributeDefinition` in a separate `*Config` `@interface`.
- **Package visibility**: public API lives in `org.apache.sling.auth.form`; implementation classes live under `.impl` and must not be exported (enforced by `bnd.bnd`).
- **Servlet APIs**: both `jakarta.servlet` and `javax.servlet` are present as provided dependencies; prefer Jakarta APIs in new code.
- **No framework-specific utilities** beyond Sling/OSGi — use `org.apache.commons.codec` (bundled via `Conditional-Package`) and `commons-lang3` (provided scope).
- **Logging**: SLF4J 2.x (`org.slf4j.Logger`) only.
- **4-space indentation**, standard Java naming conventions.
- All source files must carry the Apache License 2.0 header.
- `bnd.bnd` controls bundle manifest; do not edit `MANIFEST.MF` directly.

# Git Workflow

- Follow Apache Sling conventions: https://sling.apache.org/contributing.html
- Branch from `master`; name branches after the JIRA issue (e.g., `SLING-12345`).
- Commit messages: start with the JIRA key: `SLING-XXXXX Description of change`.
- No force-push to `master`. PRs are merged by committers after review.
- `.git-blame-ignore-revs` lists reformatting commits; configure locally with `git config blame.ignoreRevsFile .git-blame-ignore-revs`.

# Testing Guidelines

- **Unit tests**: JUnit 4 + Mockito + `org.apache.sling.testing.osgi-mock.junit4`.
- **Integration tests**: Pax Exam 4 running a forked OSGi container with Sling Pax Exam support.
- Class names for integration tests must end in `IT` and live under `src/test/java/.../it/` to be picked up by `maven-failsafe-plugin`.
- Run unit tests: `mvn test`
- Run all tests including IT: `mvn verify`
- Coverage: `mvn verify -Pjacoco-report` — report in `target/site/jacoco/`.
- Integration tests need the built JAR (`target/*.jar`) present; run `mvn package` before running IT tests in isolation.

# Gotchas

- **Optional JAAS integration**: `FormLoginModulePlugin` and `jaas/` classes depend on `org.apache.felix.jaas` and `oak-core`, both `optional` in scope. Guard with null checks / `JaasHelper.isAvailable()`.
- **Token store file**: `TokenStore` writes a secret key file to the filesystem path configured in `FormAuthenticationHandlerConfig`. In tests, this path must be writable and cleaned up.
- **Cookie vs session storage**: default is cookie (`sling.formauth` cookie). Session storage mode stores the token in `HttpSession` — remember this affects clustering behavior.
- **Integration test isolation**: each `*IT` class starts its own Pax Exam container; running multiple IT classes in the same JVM can cause port conflicts.
- **Failsafe wiring**: integration test and verify goals are bound via `maven-failsafe-plugin`; keep this when adjusting test execution phases.
- **`Conditional-Package`**: `commons-codec` classes are inlined into the bundle (see `bnd.bnd`). Do not add a runtime `Import-Package` for `org.apache.commons.codec`.
- **Java version**: the parent POM pins `sling.java.version=17`; do not use `--release` flags lower than 17 in compiler args.

# Security

<!-- sling-security-default:start -->
The threat model for this project is https://github.com/apache/sling/blob/master/docs/threat-model.md .
<!-- sling-security-default:end -->
