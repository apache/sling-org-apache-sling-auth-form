/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sling.auth.form.it;

import javax.inject.Inject;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.felix.hc.api.Result;
import org.apache.felix.hc.api.ResultLog;
import org.apache.felix.hc.api.execution.HealthCheckExecutionResult;
import org.apache.felix.hc.api.execution.HealthCheckExecutor;
import org.apache.felix.hc.api.execution.HealthCheckSelector;
import org.apache.sling.testing.paxexam.TestSupport;
import org.ops4j.pax.exam.Configuration;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.options.ModifiableCompositeOption;
import org.ops4j.pax.exam.options.extra.VMOption;
import org.ops4j.pax.tinybundles.core.TinyBundle;
import org.ops4j.pax.tinybundles.core.TinyBundles;
import org.osgi.framework.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.felix.hc.api.FormattingResultLog.msHumanReadable;
import static org.apache.sling.testing.paxexam.SlingOptions.awaitility;
import static org.apache.sling.testing.paxexam.SlingOptions.slingQuickstartOakTar;
import static org.apache.sling.testing.paxexam.SlingOptions.versionResolver;
import static org.awaitility.Awaitility.await;
import static org.junit.Assert.assertNotNull;
import static org.ops4j.pax.exam.CoreOptions.composite;
import static org.ops4j.pax.exam.CoreOptions.junitBundles;
import static org.ops4j.pax.exam.CoreOptions.mavenBundle;
import static org.ops4j.pax.exam.CoreOptions.options;
import static org.ops4j.pax.exam.CoreOptions.streamBundle;
import static org.ops4j.pax.exam.CoreOptions.vmOption;
import static org.ops4j.pax.exam.CoreOptions.when;
import static org.ops4j.pax.exam.cm.ConfigurationAdminOptions.factoryConfiguration;
import static org.ops4j.pax.tinybundles.core.TinyBundles.withBnd;

public abstract class AuthFormTestSupport extends TestSupport {
    private static final String BUNDLE_SYMBOLICNAME = "TEST-CONTENT-BUNDLE";
    private static final String SLING_BUNDLE_RESOURCES_HEADER = "Sling-Bundle-Resources";

    protected static final String FORM_AUTH_VERIFY_USER = "form-auth-user";
    protected static final String FORM_AUTH_VERIFY_PWD = "testing";

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    @Inject
    private HealthCheckExecutor hcExecutor;

    @Configuration
    public Option[] configuration() throws IOException {
        final String vmOpt = System.getProperty("pax.vm.options");
        VMOption vmOption = null;
        if (vmOpt != null && !vmOpt.isEmpty()) {
            vmOption = new VMOption(vmOpt);
        }

        final String jacocoOpt = System.getProperty("jacoco.command");
        VMOption jacocoCommand = null;
        if (jacocoOpt != null && !jacocoOpt.isEmpty()) {
            jacocoCommand = new VMOption(jacocoOpt);
        }

        // SLING-12573 - Java 21 support was added in ASM 9.5
        //   NOTE: remove this block when the versionResolver defaults to this version of asm* or later
        versionResolver.setVersion("org.ow2.asm", "asm", "9.5");
        versionResolver.setVersion("org.ow2.asm", "asm-analysis", "9.5");
        versionResolver.setVersion("org.ow2.asm", "asm", "9.5");
        versionResolver.setVersion("org.ow2.asm", "asm-commons", "9.5");
        versionResolver.setVersion("org.ow2.asm", "asm-util", "9.5");
        versionResolver.setVersion("org.ow2.asm", "asm-tree", "9.5");

        return options(composite(
                        super.baseConfiguration(),
                        when(vmOption != null).useOptions(vmOption),
                        when(jacocoCommand != null).useOptions(jacocoCommand),
                        optionalRemoteDebug(),
                        slingQuickstart(),
                        testBundle("bundle.filename"),
                        // testing - ensure that the /content path is accessible to everyone
                        //   NOTE: required since update to o.a.sling.testing.paxexam 4.x as the 3.x version already did
                        // this step
                        factoryConfiguration("org.apache.sling.jcr.repoinit.RepositoryInitializer")
                                .put("scripts", new String[] {
                                    "create path (sling:OrderedFolder) /content\nset ACL for everyone\n      allow   jcr:read    on /content\n  end"
                                })
                                .asOption(),
                        // testing - add a user to use to login and verify the content loading has happened
                        factoryConfiguration("org.apache.sling.jcr.repoinit.RepositoryInitializer")
                                .put("scripts", new String[] {
                                    "create user " + FORM_AUTH_VERIFY_USER + " with password " + FORM_AUTH_VERIFY_PWD
                                            + "\n"
                                })
                                .asOption(),
                        junitBundles(),
                        awaitility())
                .add(additionalOptions())
                .remove(
                        // remove our bundle under test to avoid duplication
                        mavenBundle()
                                .groupId("org.apache.sling")
                                .artifactId("org.apache.sling.auth.form")
                                .version(versionResolver)));
    }

    protected Option[] additionalOptions() throws IOException { // NOSONAR
        return new Option[] {};
    }

    protected Option slingQuickstart() {
        final String workingDirectory = workingDirectory();
        final int httpPort = findFreePort();
        return composite(slingQuickstartOakTar(workingDirectory, httpPort));
    }

    public String getTestFileUrl(String path) {
        return getClass().getResource(path).toExternalForm();
    }

    /**
     * Optionally configure remote debugging on the port supplied by the "debugPort"
     * system property.
     */
    protected ModifiableCompositeOption optionalRemoteDebug() {
        VMOption option = null;
        String property = System.getProperty("debugPort");
        if (property != null) {
            option = vmOption(String.format("-Xrunjdwp:transport=dt_socket,server=y,suspend=y,address=%s", property));
        }
        return composite(option);
    }

    /**
     * Wait for the health check to be ok
     *
     * @param timeoutMsec the max time to wait for the health check to be ok
     * @param nextIterationDelay the sleep time between the check attempts
     */
    protected void waitForServerReady(long timeoutMsec, long nextIterationDelay) {
        // retry until the exec call returns true and doesn't throw any exception
        await().atMost(timeoutMsec, TimeUnit.MILLISECONDS)
                .pollInterval(nextIterationDelay, TimeUnit.MILLISECONDS)
                .until(this::doHealthCheck);
    }

    /**
     * @return true if health checks are ok
     */
    protected boolean doHealthCheck() throws IOException {
        boolean isOk = true;
        logger.info("Performing health check");
        HealthCheckSelector hcs = HealthCheckSelector.tags("systemalive");
        List<HealthCheckExecutionResult> results = hcExecutor.execute(hcs);
        logger.info("systemalive health check got {} results", results.size());
        isOk &= !results.isEmpty();
        for (final HealthCheckExecutionResult exR : results) {
            final Result r = exR.getHealthCheckResult();
            if (logger.isInfoEnabled()) {
                logger.info("systemalive health check: {}", toHealthCheckResultInfo(exR, false));
            }
            isOk &= r.isOk();
            if (!isOk) {
                break; // found a failure so stop checking further
            }
        }

        if (isOk) {
            hcs = HealthCheckSelector.tags("bundles");
            results = hcExecutor.execute(hcs);
            logger.info("bundles health check got {} results", results.size());
            isOk &= !results.isEmpty();
            for (final HealthCheckExecutionResult exR : results) {
                final Result r = exR.getHealthCheckResult();
                if (logger.isInfoEnabled()) {
                    logger.info("bundles health check: {}", toHealthCheckResultInfo(exR, false));
                }
                isOk &= r.isOk();
                if (!isOk) {
                    break; // found a failure so stop checking further
                }
            }
        }
        return isOk;
    }

    /**
     * Produce a human readable report of the health check results that is suitable for
     * debugging or writing to a log
     */
    protected String toHealthCheckResultInfo(final HealthCheckExecutionResult exResult, final boolean debug)
            throws IOException {
        String value = null;
        try (StringWriter resultWriter = new StringWriter();
                BufferedWriter writer = new BufferedWriter(resultWriter)) {
            final Result result = exResult.getHealthCheckResult();

            writer.append('"')
                    .append(exResult.getHealthCheckMetadata().getTitle())
                    .append('"');
            writer.append(" result is: ").append(result.getStatus().toString());
            writer.newLine();
            writer.append("   Finished: ")
                    .append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(exResult.getFinishedAt()) + " after "
                            + msHumanReadable(exResult.getElapsedTimeInMs()));

            for (final ResultLog.Entry e : result) {
                if (!debug && e.isDebug()) {
                    continue;
                }
                writer.newLine();
                writer.append("   ");
                writer.append(e.getStatus().toString());
                writer.append(' ');
                writer.append(e.getMessage());
                if (e.getException() != null) {
                    writer.append(" ");
                    writer.append(e.getException().toString());
                }
            }
            writer.flush();
            value = resultWriter.toString();
        }
        return value;
    }

    /**
     * Add content to our test bundle
     */
    protected void addContent(final TinyBundle bundle, String resourcePath) throws IOException {
        String pathInBundle = resourcePath;
        resourcePath = "/content" + resourcePath;
        try (final InputStream is = getClass().getResourceAsStream(resourcePath)) {
            assertNotNull("Expecting resource to be found:" + resourcePath, is);
            logger.info("Adding resource to bundle, path={}, resource={}", pathInBundle, resourcePath);
            bundle.add(pathInBundle, is);
        }
    }

    /**
     * Build a test bundle containing the specified bundle resources
     *
     * @param header the value for the {@link #SLING_BUNDLE_RESOURCES_HEADER} header
     * @param content the collection of files to embed in the tinybundle
     * @return the tinybundle Option
     */
    protected Option buildBundleResourcesBundle(final String header, final Collection<String> content)
            throws IOException {
        final TinyBundle bundle = TinyBundles.bundle();
        bundle.set(Constants.BUNDLE_SYMBOLICNAME, BUNDLE_SYMBOLICNAME);
        bundle.set(SLING_BUNDLE_RESOURCES_HEADER, header);
        bundle.set(
                "Require-Capability",
                "osgi.extender;filter:=\"(&(osgi.extender=org.apache.sling.bundleresource)(version<=1.1.0)(!(version>=2.0.0)))\"");

        for (final String entry : content) {
            addContent(bundle, entry);
        }
        return streamBundle(bundle.build(withBnd())).start();
    }
}
