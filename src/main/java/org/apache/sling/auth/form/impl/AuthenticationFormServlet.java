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

import javax.servlet.Servlet;
import javax.servlet.http.HttpServletRequest;

import org.apache.sling.auth.core.spi.AbstractAuthenticationFormServlet;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.form.FormReason;
import org.osgi.service.component.annotations.Component;

/**
 * The <code>AuthenticationFormServlet</code> provides the default login form
 * used for Form Based Authentication.
 */
@Component(service = Servlet.class, property = { "sling.auth.requirements=" + AuthenticationFormServlet.AUTH_REQUIREMENTS,
        "sling.servlet.paths=" + AuthenticationFormServlet.SERVLET_PATH,
        "service.description=Default Login Form for Form Based Authentication" })
public class AuthenticationFormServlet extends AbstractAuthenticationFormServlet {

    public static final String SERVLET_PATH = "/system/sling/form/login";
    public static final String AUTH_REQUIREMENTS = "-" + SERVLET_PATH;

    private static final long serialVersionUID = -1497963620502763188L;

    /**
     * Returns an informational message according to the value provided in the
     * <code>j_reason</code> request parameter. Supported reasons are invalid
     * credentials and session timeout.
     *
     * @param request
     *            The request providing the parameter
     * @return The "translated" reason to render the login form or an empty string
     *         if there is no specific reason
     */
    @Override
    protected String getReason(final HttpServletRequest request) {
        // return the resource attribute if set to a non-empty string
        Object resObj = request.getAttribute(AuthenticationHandler.FAILURE_REASON);
        if (resObj instanceof FormReason) {
            return ((FormReason) resObj).toString();
        }

        final String reason = request.getParameter(AuthenticationHandler.FAILURE_REASON);
        if (reason != null) {
            try {
                return FormReason.valueOf(reason).toString();
            } catch (IllegalArgumentException iae) {
                // thrown if the reason is not an expected value, assume none
            }

            // no valid FormReason value, use raw value
            return reason;
        }

        return "";
    }
}
