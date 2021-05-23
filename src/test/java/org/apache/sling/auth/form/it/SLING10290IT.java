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

import static org.apache.sling.testing.paxexam.SlingOptions.slingScriptingSightly;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.ops4j.pax.exam.cm.ConfigurationAdminOptions.factoryConfiguration;
import static org.ops4j.pax.exam.cm.ConfigurationAdminOptions.newConfiguration;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Dictionary;
import java.util.List;

import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.cookie.Cookie;
import org.apache.http.cookie.CookieOrigin;
import org.apache.http.cookie.CookieSpec;
import org.apache.http.cookie.MalformedCookieException;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.cookie.RFC6265StrictSpec;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;

/**
 * integration tests to verify fix for SLING-10290
 */
@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class SLING10290IT extends AuthFormTestSupport {

    @Inject
    private ConfigurationAdmin cm;

    private static final String COOKIE_SLING_FORMAUTH = "sling.formauth";
    private static final String HEADER_SET_COOKIE = "Set-Cookie";

    private URI baseServerUri;
    private HttpClientContext httpContext;
    private CloseableHttpClient httpClient;

    @Override
    protected Option[] additionalOptions() throws IOException {
        // create a tinybundle that contains a test script
        final List<String> resourcePaths = Arrays.asList("/apps/sling/OrderedFolder/SLING10290IT.html");
        final String bundleResourcesHeader = String.join(",", resourcePaths);
        final Option bundle = buildBundleResourcesBundle(bundleResourcesHeader, resourcePaths);

        return new Option[]{
            // add sightly support for the test script
            slingScriptingSightly(),

            // add the test script tinybundle
            bundle,

            // change the formauth timeout to 1 minute so we don't have to wait a long
            //   time for the testRefreshCookieOnRequestAfterHalfExpirationDuration test
            newConfiguration("org.apache.sling.auth.form.FormAuthenticationHandler")
                .put("form.auth.timeout", "1")
            .asOption(),

            // enable the healthcheck configuration for checking when the server is ready to
            //  receive http requests.  (adapted from the starter healthcheck.json configuration)
            factoryConfiguration("org.apache.felix.hc.generalchecks.FrameworkStartCheck")
                .put("hc.tags", new String[] {"systemalive"})
                .put("targetStartLevel", 5)
                .asOption(),
            factoryConfiguration("org.apache.felix.hc.generalchecks.ServicesCheck")
                .put("hc.tags", new String[] {"systemalive"})
                .put("services.list", new String[] {
                        "org.apache.sling.jcr.api.SlingRepository",
                        "org.apache.sling.engine.auth.Authenticator",
                        "org.apache.sling.api.resource.ResourceResolverFactory",
                        "org.apache.sling.api.servlets.ServletResolver",
                        "javax.script.ScriptEngineManager"
                })
                .asOption(),
            factoryConfiguration("org.apache.felix.hc.generalchecks.BundlesStartedCheck")
                .put("hc.tags", new String[] {"bundles"})
                .asOption(),
            factoryConfiguration("org.apache.sling.jcr.contentloader.hc.BundleContentLoadedCheck")
                .put("hc.tags", new String[] {"bundles"})
                .asOption(),
        };
    }

    @Before
    public void before() throws IOException, URISyntaxException {
        // wait for the health checks to be OK
        waitForServerReady(Duration.ofMinutes(1).toMillis(), 500);

        // calculate the address of the http server
        baseServerUri = getBaseServerUri();
        assertNotNull(baseServerUri);

        // prepare the http client for the test user
        httpContext = HttpClientContext.create();
        httpContext.setCookieStore(new BasicCookieStore());
        RequestConfig requestConfig = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD_STRICT).build();
        httpContext.setRequestConfig(requestConfig);
        httpClient = HttpClients.custom()
                .disableRedirectHandling()
                .build();
    }

    @After
    public void after() throws IOException {
        // close/cleanup the test user http client
        if (httpClient != null) {
            httpClient.close();
            httpClient = null;
        }

        // clear out other state
        httpContext = null;
        baseServerUri = null;
    }

    @Test
    public void testLoginFormRenders() throws IOException {
        HttpGet loginformRequest = new HttpGet(String.format("%s/system/sling/form/login", baseServerUri));
        try (CloseableHttpResponse loginformResponse = httpClient.execute(loginformRequest, httpContext)) {
            assertEquals(HttpServletResponse.SC_OK, loginformResponse.getStatusLine().getStatusCode());
            String content = EntityUtils.toString(loginformResponse.getEntity());
            assertTrue(content.contains("Login to Apache Sling"));
            assertTrue(content.contains("loginform"));
        }
    }

    @Test
    public void testLogout() throws IOException, MalformedCookieException {
        doFormsLogin();
        HttpGet logoutRequest = new HttpGet(String.format("%s/system/sling/logout", baseServerUri));
        try (CloseableHttpResponse logoutResponse = httpClient.execute(logoutRequest, httpContext)) {
            assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY, logoutResponse.getStatusLine().getStatusCode());
            Cookie parsedFormauthCookie = parseFormAuthCookieFromHeaders(logoutResponse);
            assertNotNull("Expected a formauth cookie in the response", parsedFormauthCookie);
            assertEquals("Expected the formauth cookie value to be empty", "", parsedFormauthCookie.getValue());
            assertTrue("Expected the formauth cookie to be expired", parsedFormauthCookie.isExpired(new Date()));
            Cookie formauthCookie2 = getFormAuthCookieFromCookieStore();
            assertNull("Did not expected a formauth cookie in the cookie store", formauthCookie2);
        }
    }

    /**
     * Verify that the formauth cookie is sent appropriately after login
     */
    @Test
    public void testSetCookieOnFirstRequestAfterLogin() throws MalformedCookieException, IOException {
        doFormsLogin();
    }

    /**
     * Verify that the formauth cookie is not re-sent on each request after login
     */
    @Test
    public void testNoSetCookieOnSecondRequestAfterLogin() throws MalformedCookieException, IOException {
        // 1. login as the test user
        doFormsLogin();

        // 2. do another request
        HttpGet request = new HttpGet(whoamiUri());
        try (CloseableHttpResponse response = httpClient.execute(request, httpContext)) {
            assertEquals(HttpServletResponse.SC_OK, response.getStatusLine().getStatusCode());
            Cookie parsedFormauthCookie = parseFormAuthCookieFromHeaders(response);
            assertNull("Did not expect a formauth cookie in the response", parsedFormauthCookie);
        }
    }

    /**
     * Verify that the formauth cookie is refreshed on the first request after half the session duration
     * has occurred
     */
    @Test
    public void testRefreshCookieOnRequestAfterHalfExpirationDuration() throws InterruptedException, MalformedCookieException, IOException {
        // 1. login as the test user
        doFormsLogin();

        // 2. wait for half the session timeout expiration duration
        Thread.sleep((Duration.ofMinutes(1).toMillis() / 2) + 1); // NOSONAR

        // 3. do another request to trigger the cookie refresh
        HttpGet request = new HttpGet(whoamiUri());
        try (CloseableHttpResponse response = httpClient.execute(request, httpContext)) {
            assertEquals(HttpServletResponse.SC_OK, response.getStatusLine().getStatusCode());
            Cookie parsedFormauthCookie = parseFormAuthCookieFromHeaders(response);
            assertNotNull("Expected a refreshed formauth cookie in the response", parsedFormauthCookie);
        }

        // 4. do another request to verify that subsequent request after
        //    the cookie refresh do not send an additional formauth cookie
        try (CloseableHttpResponse response = httpClient.execute(request, httpContext)) {
            assertEquals(HttpServletResponse.SC_OK, response.getStatusLine().getStatusCode());
            Cookie parsedFormauthCookie2 = parseFormAuthCookieFromHeaders(response);
            assertNull("Did not expect a formauth cookie in the response", parsedFormauthCookie2);
        }
    }

    /**
     * Calculate the base server URI from the current configuration of the
     * httpservice
     */
    private URI getBaseServerUri() throws IOException, URISyntaxException {
        assertNotNull(cm);
        Configuration httpServiceConfiguration = cm.getConfiguration("org.apache.felix.http");
        Dictionary<String, Object> properties = httpServiceConfiguration.getProperties();

        String host;
        Object hostObj = properties.get("org.apache.felix.http.host");
        if (hostObj == null) {
            host = "localhost";
        } else {
            assertTrue(hostObj instanceof String);
            host = (String)hostObj;
        }
        assertNotNull(host);

        String scheme = null;
        Object portObj = null;
        Object httpsEnableObj = properties.get("org.apache.felix.https.enable");
        if ("true".equals(httpsEnableObj)) {
            scheme = "https";
            portObj = properties.get("org.osgi.service.http.port.secure");
        } else {
            Object httpEnableObj = properties.get("org.apache.felix.http.enable");
            if (httpEnableObj == null || "true".equals(httpEnableObj)) {
                scheme = "http";
                portObj = properties.get("org.osgi.service.http.port");
            } else {
                fail("Expected either http or https to be enabled");
            }
        }
        int port = -1;
        if (portObj instanceof Number) {
            port = ((Number)portObj).intValue();
        }
        assertTrue(port > 0);

        return new URI(String.format("%s://%s:%d", scheme, host, port));
    }

    /**
     * @return the address of the whoami script
     */
    private String whoamiUri() {
        return String.format("%s/content.SLING10290IT.html", baseServerUri);
    }

    /**
     * Perform the http calls to login the test user via the forms based login
     */
    private void doFormsLogin() throws MalformedCookieException, IOException {
        // before login, there should be no formauth cookie in the cookie store
        Cookie formauthCookie = getFormAuthCookieFromCookieStore();
        assertNull("Did not expect formauth cookie in the cookie store", formauthCookie);

        // verify that the script shows us as not logged in
        HttpGet whoamiRequest = new HttpGet(whoamiUri());
        try (CloseableHttpResponse whoamiResponse = httpClient.execute(whoamiRequest, httpContext)) {
            assertEquals(HttpServletResponse.SC_OK, whoamiResponse.getStatusLine().getStatusCode());
            String content = EntityUtils.toString(whoamiResponse.getEntity());
            assertTrue(content.contains("whoAmI"));
            assertTrue(content.contains("anonymous"));
        }

        // send the form login request
        List<NameValuePair> parameters = new ArrayList<>();
        parameters.add(new BasicNameValuePair("j_username", FORM_AUTH_VERIFY_USER));
        parameters.add(new BasicNameValuePair("j_password", FORM_AUTH_VERIFY_PWD));
        parameters.add(new BasicNameValuePair("_charset_", StandardCharsets.UTF_8.name()));
        parameters.add(new BasicNameValuePair("resource", "/content.SLING10290IT.html"));
        HttpPost request = new HttpPost(String.format("%s/j_security_check", baseServerUri));
        request.setEntity(new UrlEncodedFormEntity(parameters));
        Header locationHeader = null; 
        try (CloseableHttpResponse response = httpClient.execute(request, httpContext)) {
            assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY, response.getStatusLine().getStatusCode());
            locationHeader = response.getFirstHeader("Location");

            // verify that the expected set-cookie header arrived
            Cookie parsedFormauthCookie = parseFormAuthCookieFromHeaders(response);
            assertNotNull("Expected a formauth cookie in the response", parsedFormauthCookie);
        }

        // after login, there should be now be a cookie in the cookie store
        Cookie formauthCookie2 = getFormAuthCookieFromCookieStore();
        assertNotNull("Expected a formauth cookie in the cookie store", formauthCookie2);

        // and then follow the redirect
        assertNotNull("Expected a 'Location' header", locationHeader);
        // verify that the script shows us logged in as the test user
        HttpGet followedRequest = new HttpGet(locationHeader.getValue());
        try (CloseableHttpResponse followedResponse = httpClient.execute(followedRequest, httpContext)) {
            assertEquals(HttpServletResponse.SC_OK, followedResponse.getStatusLine().getStatusCode());
            String content = EntityUtils.toString(followedResponse.getEntity());
            assertTrue(content.contains("whoAmI"));
            assertTrue(content.contains(FORM_AUTH_VERIFY_USER));

            // there should be no new formauth cookie on the followed response
            Cookie parsedFormauthCookie2 = parseFormAuthCookieFromHeaders(followedResponse);
            assertNull("Did not expect a formauth cookie in the response", parsedFormauthCookie2);
        }
    }

    /**
     * Retrieve the formauth cookie from the cookie store
     * 
     * @return the formauth cookie or null if not found
     */
    private Cookie getFormAuthCookieFromCookieStore() {
        Cookie formauthCookie = null;
        List<Cookie> cookies = httpContext.getCookieStore().getCookies();
        if (cookies != null) {
            for (Cookie c : cookies) {
                if (COOKIE_SLING_FORMAUTH.equals(c.getName())) {
                    formauthCookie = c;
                }
            }
        }
        return formauthCookie;
    }

    /**
     * Parse the formauth cookie out of the headers sent on the response
     *
     * @param response the response from the http request
     * @return the found cookie or null if not found
     */
    private Cookie parseFormAuthCookieFromHeaders(HttpResponse response) throws MalformedCookieException {
        Header [] cookieHeaders = response.getHeaders(HEADER_SET_COOKIE);
        assertNotNull(cookieHeaders);

        Cookie parsedFormauthCookie = null;
        CookieSpec cookieSpec = new RFC6265StrictSpec();
        CookieOrigin origin = new CookieOrigin(baseServerUri.getHost(), baseServerUri.getPort(),
                baseServerUri.getPath(), "https".equals(baseServerUri.getScheme()));
        for (Header cookieHeader : cookieHeaders) {
            List<Cookie> parsedCookies = cookieSpec.parse(cookieHeader, origin);
            for (Cookie c : parsedCookies) {
                if (COOKIE_SLING_FORMAUTH.equals(c.getName())) {
                    if (parsedFormauthCookie != null) {
                        fail(String.format("Did not expect more than one %s cookie", c.getName()));
                    }
                    parsedFormauthCookie = c;
                }
            }
        }
        return parsedFormauthCookie;
    }

}
