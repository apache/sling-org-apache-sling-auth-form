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
package org.apache.sling.auth.form.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.util.Collections;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.sling.api.auth.Authenticator;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.testing.mock.osgi.MockBundle;
import org.apache.sling.testing.mock.osgi.junit.OsgiContext;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;

public class FormAuthenticationHandlerTest {

    @Rule
    public final OsgiContext context = new OsgiContext();

    @Before
    public void before() {
        // workaround the downstream code requiring the bundle context to have a vender header
        MockBundle mockBundle = (MockBundle) context.bundleContext().getBundle();
        mockBundle.setHeaders(Collections.singletonMap(Constants.BUNDLE_VENDOR, "Testing"));
    }

    @Test public void testGetTokenFile() {
      final File root = new File("bundle999").getAbsoluteFile();
      final String slingHome = new File("sling").getAbsolutePath();
      final BundleContext bundleContext = spy(context.bundleContext());

      // mock access to sling.home framework property
      when(bundleContext.getProperty("sling.home"))
          .thenReturn(slingHome);
      // mock data file support
      when(bundleContext.getDataFile(anyString()))
          .thenAnswer(invocation -> {
              String data = (String) invocation.getArgument(0);
              // mock no data file support with file names starting with sl
              if (data.startsWith("sl")) {
                  return null;
              }

              // mock data file support for any other name
              if (data.startsWith("/")) {
                  data = data.substring(1);
              }
              return new File(root, data);
          });

        final FormAuthenticationHandler handler = context.registerInjectActivateService(FormAuthenticationHandler.class);

        // test files relative to bundle context
        File relFile0 = handler.getTokenFile("", bundleContext);
        assertEquals(root, relFile0);

        String relName1 = "rel/path";
        File relFile1 = handler.getTokenFile(relName1, bundleContext);
        assertEquals(new File(root, relName1), relFile1);

        // test file relative to sling.home if no data file support
        String relName2 = "sl/rel_to_sling.home";
        File relFile2 = handler.getTokenFile(relName2, bundleContext);
        assertEquals(new File(slingHome, relName2), relFile2);

        // test file relative to current working directory
        String relName3 = "sl/test";
        when(bundleContext.getProperty("sling.home"))
            .thenReturn(null);
        File relFile3 = handler.getTokenFile(relName3, bundleContext);
        assertEquals(new File(relName3).getAbsoluteFile(), relFile3);

        // test absolute file return
        File absFile = new File("test").getAbsoluteFile();
        File absFile0 = handler.getTokenFile(absFile.getPath(), bundleContext);
        assertEquals(absFile, absFile0);
    }

    @Test public void testGetUserid() {
        final FormAuthenticationHandler handler = context.registerInjectActivateService(FormAuthenticationHandler.class);
        assertEquals(null, handler.getUserId(null));
        assertEquals(null, handler.getUserId(""));
        assertEquals(null, handler.getUserId("field0"));
        assertEquals(null, handler.getUserId("field0@field1"));
        assertEquals("field3", handler.getUserId("field0@field1@field3"));
        assertEquals("field3@field4", handler.getUserId("field0@field1@field3@field4"));
    }

    /**
     * Test for SLING-3443 Parameter based redirection should only handle relative paths
     * @throws Exception UrlEncoder.encode throws UnsupportedEncodingException
     * @since 1.0.6
     */
    @Test public void testRedirectionAfterLogin() throws Exception {
        // Create mocks
        final HttpServletRequest request =  mock(HttpServletRequest.class);
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final AuthenticationInfo authenticationInfo = mock(AuthenticationInfo.class);

        final FormAuthenticationHandler authenticationHandler = context.registerInjectActivateService(FormAuthenticationHandler.class);

        // Mocks the Authenticator.LOGIN_RESOURCE attribute
        final String url = "http://www.blah.com";
        when(request.getAttribute(Authenticator.LOGIN_RESOURCE))
            .thenReturn(url);

        // Mocks the HttpServletRequest and HttpServletResponse object
        when(request.getMethod()).thenReturn("POST");
        when(request.getRequestURI()).thenReturn("http://blah/blah/j_security_check");
        String contextPath = "/blah"; // NOSONAR
        when(request.getContextPath()).thenReturn(contextPath);
        when(response.isCommitted()).thenReturn(false);

        // Test the method
        assertTrue(authenticationHandler.authenticationSucceeded(request, response, authenticationInfo));

        // Verify mocks
        verify(response).resetBuffer();
        // The request should be redirected to the context root rather than the
        // passing the parameter directly
        verify(response).sendRedirect(contextPath);
    }

}
