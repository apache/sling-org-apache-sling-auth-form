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
import java.util.Date;

import jakarta.servlet.http.HttpServletResponse;
import org.apache.http.client.CookieStore;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.cookie.Cookie;
import org.apache.http.cookie.MalformedCookieException;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.ops4j.pax.exam.cm.ConfigurationAdminOptions.newConfiguration;

/**
 * SLING-10421 validate proper cookie handling when the formauth
 * handler has been configured with an invalid cookie domain
 */
@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class SLING10421InvalidDomainIT extends AuthFormClientTestSupport {

    @Override
    protected Option newFormauthHandlerConfiguration() {
        // change the default cookie domain config
        return newConfiguration("org.apache.sling.auth.form.FormAuthenticationHandler")
                .put("form.default.cookie.domain", "invalid")
                .asOption();
    }

    /**
     * SLING-10421 validate configured and client supplied cookie domain value
     */
    @Test
    public void testLoginWithInvalidConfiguredCookieDomain() throws IOException, MalformedCookieException {
        doFormsLogin();
    }

    /**
     * SLING-10421 validate configured and client supplied cookie domain value
     */
    @Test
    public void testLogoutWithInvalidConfiguredCookieDomain() throws IOException, MalformedCookieException {
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
            assertEquals(
                    "Expected the formauth cookie domain to be localhost",
                    "localhost",
                    parsedFormauthCookie.getDomain());

            Cookie parsedFormauthDomainCookie = parseCookieFromHeaders(logoutResponse, COOKIE_SLING_FORMAUTH_DOMAIN);
            assertNull("Did not expected a formauth domain cookie in the response", parsedFormauthDomainCookie);

            Cookie formauthCookie2 = getFormAuthCookieFromCookieStore();
            assertNull("Did not expected a formauth cookie in the cookie store", formauthCookie2);

            Cookie formauthDomainCookie2 = getCookieFromCookieStore(COOKIE_SLING_FORMAUTH_DOMAIN);
            assertNull("Did not expected a formauth domain cookie in the cookie store", formauthDomainCookie2);
        }
    }

    /**
     * SLING-10421 validate configured and client supplied cookie domain value
     */
    @Test
    public void testLogoutWithInvalidDomainCookieValue() throws IOException, MalformedCookieException {
        doFormsLogin();

        // add an invalid domain cookie to the cookie store
        CookieStore cookieStore = httpContext.getCookieStore();
        BasicClientCookie invalidCookie = new BasicClientCookie(COOKIE_SLING_FORMAUTH_DOMAIN, "invalid");
        invalidCookie.setPath("/");
        invalidCookie.setDomain("localhost");
        cookieStore.addCookie(invalidCookie);

        HttpGet logoutRequest = new HttpGet(String.format("%s/system/sling/logout", baseServerUri));
        try (CloseableHttpResponse logoutResponse = httpClient.execute(logoutRequest, httpContext)) {
            assertEquals(
                    HttpServletResponse.SC_MOVED_TEMPORARILY,
                    logoutResponse.getStatusLine().getStatusCode());
            Cookie parsedFormauthCookie = parseFormAuthCookieFromHeaders(logoutResponse);
            assertNotNull("Expected a formauth cookie in the response", parsedFormauthCookie);
            assertEquals("Expected the formauth cookie value to be empty", "", parsedFormauthCookie.getValue());
            assertTrue("Expected the formauth cookie to be expired", parsedFormauthCookie.isExpired(new Date()));
            assertEquals(
                    "Expected the formauth cookie domain to be localhost",
                    "localhost",
                    parsedFormauthCookie.getDomain());

            Cookie parsedFormauthDomainCookie = parseCookieFromHeaders(logoutResponse, COOKIE_SLING_FORMAUTH_DOMAIN);
            assertNull("Did not expected a formauth domain cookie in the response", parsedFormauthDomainCookie);

            Cookie formauthCookie2 = getFormAuthCookieFromCookieStore();
            assertNull("Did not expected a formauth cookie in the cookie store", formauthCookie2);

            Cookie formauthDomainCookie2 = getCookieFromCookieStore(COOKIE_SLING_FORMAUTH_DOMAIN);
            assertSame(
                    "Did not expected a new formauth domain cookie in the cookie store",
                    invalidCookie,
                    formauthDomainCookie2);
        }
    }

    @Override
    protected void doFormsLogin() throws MalformedCookieException, IOException {
        super.doFormsLogin(
                cookie -> assertEquals(
                        "Expected a formauth cookie with domain equal to host", "localhost", cookie.getDomain()),
                domainCookie -> assertNull("Did not expect a formauth domain cookie", domainCookie));
    }
}
