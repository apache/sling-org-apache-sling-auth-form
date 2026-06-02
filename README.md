[![Apache Sling](https://sling.apache.org/res/logos/sling.png)](https://sling.apache.org)

&#32;[![Build Status](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-auth-form/job/master/badge/icon)](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-auth-form/job/master/)&#32;[![Test Status](https://img.shields.io/jenkins/tests.svg?jobUrl=https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-auth-form/job/master/)](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-auth-form/job/master/test/?width=800&height=600)&#32;[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=apache_sling-org-apache-sling-auth-form&metric=coverage)](https://sonarcloud.io/dashboard?id=apache_sling-org-apache-sling-auth-form)&#32;[![Sonarcloud Status](https://sonarcloud.io/api/project_badges/measure?project=apache_sling-org-apache-sling-auth-form&metric=alert_status)](https://sonarcloud.io/dashboard?id=apache_sling-org-apache-sling-auth-form)&#32;[![JavaDoc](https://www.javadoc.io/badge/org.apache.sling/org.apache.sling.auth.form.svg)](https://www.javadoc.io/doc/org.apache.sling/org.apache.sling.auth.form)&#32;[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.apache.sling/org.apache.sling.auth.form/badge.svg)](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22org.apache.sling%22%20a%3A%22org.apache.sling.auth.form%22)&#32;[![auth](https://sling.apache.org/badges/group-auth.svg)](https://github.com/apache/sling-aggregator/blob/master/docs/groups/auth.md) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

# Apache Sling Form Based Authentication Handler

Bundle implementing form based authentication with login and logout support.
Authentication state is maintained in a Cookie or in an HTTP Session. The
password is only submitted when first authenticating.

This bundle targets **Java 17** and current Sling Auth Core / Sling API releases,
including Jakarta Servlet support.

## Features

* Form-based login/logout via `JakartaAuthenticationHandler`
* Authentication state persisted in either:
  * signed cookie tokens (`sling.formauth`, default), or
  * HTTP session attributes
* Standalone default login form servlet at `/system/sling/form/login`
  (template: `src/main/resources/org/apache/sling/auth/form/impl/login.html`)
* Optional JAAS integration through `FormLoginModulePlugin`

## Build and test

```bash
# Build and package the bundle
mvn clean package

# Run unit tests
mvn test

# Run a single test class
mvn test -Dtest=TokenStoreTest

# Run unit + integration tests (Pax Exam)
mvn verify

# Run integration tests only
mvn failsafe:integration-test failsafe:verify

# Generate JaCoCo report
mvn verify -Pjacoco-report
```

## Project layout

```
pom.xml                        Maven build descriptor
bnd.bnd                        OSGi bundle manifest instructions
src/
  main/
    java/org/apache/sling/auth/form/
      FormReason.java
      impl/
        FormAuthenticationHandler.java
        FormAuthenticationHandlerConfig.java
        AuthenticationFormServlet.java
        TokenStore.java
        FormLoginModulePlugin.java
        jaas/
    resources/
      OSGI-INF/l10n/
      org/apache/sling/auth/form/impl/login.html
  test/
    java/
      org/apache/sling/auth/form/impl/
      org/apache/sling/auth/form/it/
```

## Documentation

This module is part of the [Apache Sling](https://sling.apache.org) project.
For module documentation, see
[Form-Based Authentication Handler](https://sling.apache.org/site/form-based-authenticationhandler.html).
