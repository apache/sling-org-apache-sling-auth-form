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

import java.io.IOException;
import java.time.Duration;
import java.util.Date;

import jakarta.servlet.http.HttpServletResponse;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.cookie.Cookie;
import org.apache.http.cookie.MalformedCookieException;
import org.apache.http.util.EntityUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.ops4j.pax.exam.cm.ConfigurationAdminOptions.newConfiguration;

/**
 * integration tests to verify fix for SLING-10290
 */
@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class SLING10290IT extends AuthFormClientTestSupport {

    @Override
    protected Option newFormauthHandlerConfiguration() {
        // change the formauth timeout to 1 minute so we don't have to wait a long
        //   time for the testRefreshCookieOnRequestAfterHalfExpirationDuration test
        return newConfiguration("org.apache.sling.auth.form.FormAuthenticationHandler")
                .put("form.auth.timeout", "1")
                .asOption();
    }

    @Test
    public void testLoginFormRenders() throws IOException {
        HttpGet loginformRequest = new HttpGet(String.format("%s/system/sling/form/login", baseServerUri));
        try (CloseableHttpResponse loginformResponse = httpClient.execute(loginformRequest, httpContext)) {
            assertEquals(
                    HttpServletResponse.SC_OK, loginformResponse.getStatusLine().getStatusCode());
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
            assertEquals(
                    HttpServletResponse.SC_MOVED_TEMPORARILY,
                    logoutResponse.getStatusLine().getStatusCode());
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
        doFormsLogin(
                cookie -> assertNotNull("Expected a formauth cookie", cookie),
                domainCookie -> assertNull("Did not expect a formauth domain cookie", domainCookie));
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
    public void testRefreshCookieOnRequestAfterHalfExpirationDuration()
            throws InterruptedException, MalformedCookieException, IOException {
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
}
