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

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

import javax.jcr.Credentials;
import javax.jcr.SimpleCredentials;
import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.apache.sling.api.auth.Authenticator;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.auth.core.AuthConstants;
import org.apache.sling.auth.core.AuthUtil;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.DefaultAuthenticationFeedbackHandler;
import org.apache.sling.auth.form.FormReason;
import org.apache.sling.auth.form.impl.jaas.FormCredentials;
import org.apache.sling.auth.form.impl.jaas.JaasHelper;
import org.apache.sling.jcr.resource.api.JcrResourceConstants;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.metatype.annotations.Designate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The <code>FormAuthenticationHandler</code> class implements the authorization
 * steps based on a cookie.
 */
@Component(name = "org.apache.sling.auth.form.FormAuthenticationHandler", property = {
        AuthenticationHandler.TYPE_PROPERTY + "="
                + HttpServletRequest.FORM_AUTH }, service = AuthenticationHandler.class, immediate = true)
@Designate(ocd = FormAuthenticationHandlerConfig.class)
public class FormAuthenticationHandler extends DefaultAuthenticationFeedbackHandler implements AuthenticationHandler {

    /**
     * The request method required for user name and password submission by the form
     * (value is "POST").
     */
    private static final String REQUEST_METHOD = "POST";

    /**
     * The last segment of the request URL for the user name and password submission
     * by the form (value is "/j_security_check").
     * <p>
     * This name is derived from the prescription in the Servlet API 2.4
     * Specification, Section SRV.12.5.3.1 Login Form Notes: <i>In order for the
     * authentication to proceed appropriately, the action of the login form must
     * always be set to <code>j_security_check</code>.</i>
     */
    private static final String REQUEST_URL_SUFFIX = "/j_security_check";

    /**
     * The name of the form submission parameter providing the name of the user to
     * authenticate (value is "j_username").
     * <p>
     * This name is prescribed by the Servlet API 2.4 Specification, Section
     * SRV.12.5.3 Form Based Authentication.
     */
    private static final String PAR_J_USERNAME = "j_username";

    /**
     * The name of the form submission parameter providing the password of the user
     * to authenticate (value is "j_password").
     * <p>
     * This name is prescribed by the Servlet API 2.4 Specification, Section
     * SRV.12.5.3 Form Based Authentication.
     */
    private static final String PAR_J_PASSWORD = "j_password";

    /**
     * Key in the AuthenticationInfo map which contains the domain on which the auth
     * cookie should be set.
     */
    private static final String COOKIE_DOMAIN = "cookie.domain";

    /**
     * The factor to convert minute numbers into milliseconds used internally
     */
    private static final long MINUTES = 60L * 1000L;

    /** default log */
    private final Logger log = LoggerFactory.getLogger(getClass());

    private AuthenticationStorage authStorage;

    private String loginForm;

    /**
     * The timeout of a login session in milliseconds, converted from the
     * configuration property {@link #PAR_AUTH_TIMEOUT} by multiplying with
     * {@link #MINUTES}.
     */
    private long sessionTimeout;

    /**
     * The name of the credentials attribute which is set to the cookie data to
     * validate.
     */
    private String attrCookieAuthData;

    /**
     * The {@link TokenStore} used to persist and check authentication data
     */
    private TokenStore tokenStore;

    /**
     * The {@link FormLoginModulePlugin} service registration created when this
     * authentication handler is registered. If the login module plugin cannot be
     * created this field is set to <code>null</code>.
     */
    private ServiceRegistration<?> loginModule;

    /**
     * If true, the handler will attempt to include the login form instead of doing
     * a redirect.
     */
    private boolean includeLoginForm;

    /**
     * If true, the handler will attempt to include the reason code as a request parameter
     * instead of the reason text.
     */
    private boolean preferReasonCode;

    /**
     * The resource resolver factory used to resolve the login form as a resource
     */
    @Reference(policy = ReferencePolicy.DYNAMIC, cardinality = ReferenceCardinality.OPTIONAL)
    private volatile ResourceResolverFactory resourceResolverFactory; // NOSONAR

    /**
     * If true the login form will be presented when the token expires.
     */
    private boolean loginAfterExpire;

    private JaasHelper jaasHelper;

    /**
     * Extracts cookie/session based credentials from the request. Returns
     * <code>null</code> if the handler assumes HTTP Basic authentication would be
     * more appropriate, if no form fields are present in the request and if the
     * secure user data is not present either in the cookie or an HTTP Session.
     */
    @Override
    public AuthenticationInfo extractCredentials(HttpServletRequest request, HttpServletResponse response) {

        AuthenticationInfo info = null;

        // 1. try credentials from POST'ed request parameters
        info = this.extractRequestParameterAuthentication(request);

        // 2. try credentials from the cookie or session
        if (info == null) {
            String authData = authStorage.extractAuthenticationInfo(request);
            if (authData != null) {
                if (tokenStore.isValid(authData)) {
                    info = createAuthInfo(authData);
                } else {
                    // clear the cookie, its invalid and we should get rid of it
                    // so that the invalid cookie isn't present on the authN
                    // operation.
                    authStorage.clear(request, response);
                    if (this.loginAfterExpire || AuthUtil.isValidateRequest(request)) {
                        // signal the requestCredentials method a previous login
                        // failure
                        request.setAttribute(FAILURE_REASON, FormReason.TIMEOUT);
                        info = AuthenticationInfo.FAIL_AUTH;
                    }
                }
            }
        }

        return info;
    }

    /**
     * Unless the <code>sling:authRequestLogin</code> to anything other than
     * <code>Form</code> this method either sends back a 403/FORBIDDEN response if
     * the <code>j_verify</code> parameter is set to <code>true</code> or redirects
     * to the login form to ask for credentials.
     * <p>
     * This method assumes the <code>j_verify</code> request parameter to only be
     * set in the initial username/password submission through the login form. No
     * further checks are applied, though, before sending back the 403/FORBIDDEN
     * response.
     */
    @Override
    public boolean requestCredentials(HttpServletRequest request, HttpServletResponse response) throws IOException {

        // 0. ignore this handler if an authentication handler is requested
        if (ignoreRequestCredentials(request)) {
            // consider this handler is not used
            return false;
        }

        // check the referrer to see if the request is for this handler
        if (!AuthUtil.checkReferer(request, loginForm)) {
            // not for this handler, so return
            return false;
        }

        final String resource = AuthUtil.setLoginResourceAttribute(request, request.getRequestURI());

        if (includeLoginForm && (resourceResolverFactory != null)) {
            ResourceResolver resourceResolver = null;
            try {
                resourceResolver = resourceResolverFactory.getAdministrativeResourceResolver(null);
                Resource loginFormResource = resourceResolver.resolve(loginForm);
                Servlet loginFormServlet = loginFormResource.adaptTo(Servlet.class);
                if (loginFormServlet != null) {
                        loginFormServlet.service(request, response);
                        return true;
                }
                    } catch (ServletException e) {
                        log.error("Failed to include the form: " + loginForm, e);
            } catch (LoginException e) {
                log.error(
                        "Unable to get a resource resolver to include for the login resource. Will redirect instead.");
            } finally {
                if (resourceResolver != null) {
                    resourceResolver.close();
                }
            }
        }

        HashMap<String, String> params = new HashMap<>();
        params.put(Authenticator.LOGIN_RESOURCE, resource);

        // append indication of previous login failure
        if (preferReasonCode) {
            if (request.getAttribute(FAILURE_REASON_CODE) != null) {
                final Object jReasonCode = request.getAttribute(FAILURE_REASON_CODE);
                @SuppressWarnings("rawtypes")
                final String reasonCode = (jReasonCode instanceof Enum) ? ((Enum) jReasonCode).name() : jReasonCode.toString();
                params.put(FAILURE_REASON_CODE, reasonCode);
            }
        } else {
            if (request.getAttribute(FAILURE_REASON) != null) {
                final Object jReason = request.getAttribute(FAILURE_REASON);
                @SuppressWarnings("rawtypes")
                final String reason = (jReason instanceof Enum) ? ((Enum) jReason).name() : jReason.toString();
                params.put(FAILURE_REASON, reason);
            }
        }

        try {
            AuthUtil.sendRedirect(request, response, request.getContextPath() + loginForm, params);
        } catch (IOException e) {
            log.error("Failed to redirect to the login form " + loginForm, e);
        }

        return true;
    }

    /**
     * Clears all authentication state which might have been prepared by this
     * authentication handler.
     */
    @Override
    public void dropCredentials(HttpServletRequest request, HttpServletResponse response) {
        authStorage.clear(request, response);
    }

    // ---------- AuthenticationFeedbackHandler

    /**
     * Called after an unsuccessful login attempt. This implementation makes sure
     * the authentication data is removed either by removing the cookie or by remove
     * the HTTP Session attribute.
     */
    @Override
    public void authenticationFailed(HttpServletRequest request, HttpServletResponse response,
            AuthenticationInfo authInfo) {

        /*
         * Note: This method is called if this handler provided credentials which cause
         * a login failure
         */

        // clear authentication data from Cookie or Http Session
        authStorage.clear(request, response);

        // signal the reason for login failure
        request.setAttribute(FAILURE_REASON, FormReason.INVALID_CREDENTIALS);
    }

    /**
     * Called after successful login with the given authentication info. This
     * implementation ensures the authentication data is set in either the cookie or
     * the HTTP session with the correct security tokens.
     * <p>
     * If no authentication data already exists, it is created. Otherwise if the
     * data has expired the data is updated with a new security token and a new
     * expiry time.
     * <p>
     * If creating or updating the authentication data fails, it is actually removed
     * from the cookie or the HTTP session and future requests will not be
     * authenticated any longer.
     */
    @Override
    public boolean authenticationSucceeded(HttpServletRequest request, HttpServletResponse response,
            AuthenticationInfo authInfo) {

        /*
         * Note: This method is called if this handler provided credentials which
         * succeeded login into the repository
         */

        // ensure fresh authentication data
        refreshAuthData(request, response, authInfo);

        final boolean result;
        // SLING-1847: only consider a resource redirect if this is a POST request
        // to the j_security_check URL
        if (REQUEST_METHOD.equals(request.getMethod()) && request.getRequestURI().endsWith(REQUEST_URL_SUFFIX)) {

            if (DefaultAuthenticationFeedbackHandler.handleRedirect(request, response)) {
                // terminate request, all done in the default handler
                result = false;
            } else {
                // check whether redirect is requested by the resource parameter
                final String targetResource = AuthUtil.getLoginResource(request, null);
                if (targetResource != null) {
                    try {
                        if (response.isCommitted()) {
                            throw new IllegalStateException("Response is already committed");
                        }
                        response.resetBuffer();

                        StringBuilder b = new StringBuilder();
                        if (AuthUtil.isRedirectValid(request, targetResource)) {
                            b.append(targetResource);
                        } else if (request.getContextPath().length() == 0) {
                            b.append("/");
                        } else {
                            b.append(request.getContextPath());
                        }
                        response.sendRedirect(b.toString());
                    } catch (IOException ioe) {
                        log.error("Failed to send redirect to: " + targetResource, ioe);
                    }

                    // terminate request, all done
                    result = true;
                } else {
                    // no redirect, hence continue processing
                    result = false;
                }
            }
        } else {
            // no redirect, hence continue processing
            result = false;
        }

        // no redirect
        return result;
    }

    @Override
    public String toString() {
        return "Form Based Authentication Handler";
    }

    // --------- Force HTTP Basic Auth ---------

    /**
     * Returns <code>true</code> if this authentication handler should ignore the
     * call to {@link #requestCredentials(HttpServletRequest, HttpServletResponse)}.
     * <p>
     * This method returns <code>true</code> if the {@link #REQUEST_LOGIN_PARAMETER}
     * is set to any value other than "Form" (HttpServletRequest.FORM_AUTH).
     */
    private boolean ignoreRequestCredentials(final HttpServletRequest request) {
        final String requestLogin = request.getParameter(REQUEST_LOGIN_PARAMETER);
        return requestLogin != null && !HttpServletRequest.FORM_AUTH.equals(requestLogin);
    }

    /**
     * Ensures the authentication data is set (if not set yet) and the expiry time
     * is prolonged (if auth data already existed).
     * <p>
     * This method is intended to be called in case authentication succeeded.
     *
     * @param request
     *            The current request
     * @param response
     *            The current response
     * @param authInfo
     *            The authentication info used to successful log in
     */
    private void refreshAuthData(final HttpServletRequest request, final HttpServletResponse response,
            final AuthenticationInfo authInfo) {

        // get current authentication data, may be missing after first login
        String authData = getCookieAuthData(authInfo);

        // check whether we have to "store" or create the data
        final boolean refreshCookie = needsRefresh(authData, this.sessionTimeout);

        // add or refresh the stored auth hash
        if (refreshCookie) {
            long expires = System.currentTimeMillis() + this.sessionTimeout;
            try {
                authData = null;
                authData = tokenStore.encode(expires, authInfo.getUser());
            } catch (InvalidKeyException | IllegalStateException | NoSuchAlgorithmException e) {
                log.error(e.getMessage(), e);
            }

            if (authData != null) {
                authStorage.set(request, response, authData, authInfo);
            } else {
                authStorage.clear(request, response);
            }
        }
    }

    // --------- Request Parameter Auth ---------

    private AuthenticationInfo extractRequestParameterAuthentication(HttpServletRequest request) {
        AuthenticationInfo info = null;

        // only consider login form parameters if this is a POST request
        // to the j_security_check URL
        if (REQUEST_METHOD.equals(request.getMethod()) && request.getRequestURI().endsWith(REQUEST_URL_SUFFIX)) {

            String user = request.getParameter(PAR_J_USERNAME);
            String pwd = request.getParameter(PAR_J_PASSWORD);

            if (user != null && pwd != null) {
                info = new AuthenticationInfo(HttpServletRequest.FORM_AUTH, user, pwd.toCharArray());
                info.put(AuthConstants.AUTH_INFO_LOGIN, new Object());

                // if this request is providing form credentials, we have to
                // make sure, that the request is redirected after successful
                // authentication, otherwise the request may be processed
                // as a POST request to the j_security_check page (unless
                // the j_validate parameter is set); but only if this is not
                // a validation request
                if (!AuthUtil.isValidateRequest(request)) {
                    AuthUtil.setLoginResourceAttribute(request, request.getContextPath());
                }
            }
        }

        return info;
    }

    private AuthenticationInfo createAuthInfo(final String authData) {
        final String userId = getUserId(authData);
        if (userId == null) {
            return null;
        }

        final AuthenticationInfo info = new AuthenticationInfo(HttpServletRequest.FORM_AUTH, userId);

        if (jaasHelper.enabled()) {
            info.put(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS, new FormCredentials(userId, authData));
        } else {
            info.put(attrCookieAuthData, authData);
        }

        return info;
    }

    private String getCookieAuthData(final AuthenticationInfo info) {
        String authData = null;
        if (jaasHelper.enabled()) {
            Object credentials = info.get(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS);
            if (credentials instanceof Credentials) {
                authData = getCookieAuthData((Credentials)credentials);
            }
        } else {
            Object data = info.get(attrCookieAuthData);
            if (data instanceof String) {
                authData = (String) data;
            }
        }
        return authData;
    }

    // ---------- LoginModulePlugin support

    private String getCookieAuthData(final Credentials credentials) {
        if (credentials instanceof SimpleCredentials) {
            Object data = ((SimpleCredentials) credentials).getAttribute(attrCookieAuthData);
            if (data instanceof String) {
                return (String) data;
            }
        } else if (credentials instanceof FormCredentials) {
            return ((FormCredentials) credentials).getAuthData();
        }

        // no SimpleCredentials or no valid attribute
        return null;
    }

    boolean hasAuthData(final Credentials credentials) {
        return getCookieAuthData(credentials) != null;
    }

    public boolean isValid(final Credentials credentials) {
        String authData = getCookieAuthData(credentials);
        if (authData != null) {
            return tokenStore.isValid(authData);
        }

        // no authdata, not valid
        return false;
    }

    // ---------- SCR Integration ----------------------------------------------

    /**
     * Called by SCR to activate the authentication handler.
     *
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws IllegalStateException
     * @throws UnsupportedEncodingException
     */
    @Activate
    protected void activate(FormAuthenticationHandlerConfig config, ComponentContext componentContext)
            throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException {

        this.jaasHelper = new JaasHelper(this, componentContext.getBundleContext(), config);
        this.loginForm = config.form_login_form();
        log.info("Login Form URL {}", loginForm);

        final String authName = config.form_auth_name();

        String defaultCookieDomain = config.form_default_cookie_domain();
        if (defaultCookieDomain.length() == 0) {
            defaultCookieDomain = null;
        }

        final String formAuthStorage = config.form_auth_storage();
        if (FormAuthenticationHandlerConfig.AUTH_STORAGE_SESSION_ATTRIBUTE.equals(formAuthStorage)) {
            this.authStorage = new SessionStorage(authName);
            log.info("Using HTTP Session store with attribute name {}", authName);
        } else {
            this.authStorage = new CookieStorage(authName, defaultCookieDomain);
            log.info("Using Cookie store with name {}", authName);
        }

        this.attrCookieAuthData = config.form_credentials_name();
        log.info("Setting Auth Data attribute name {}", attrCookieAuthData);

        int timeoutMinutes = config.form_auth_timeout();
        if (timeoutMinutes < 1) {
            timeoutMinutes = FormAuthenticationHandlerConfig.DEFAULT_AUTH_TIMEOUT;
        }
        log.info("Setting session timeout {} minutes", timeoutMinutes);
        this.sessionTimeout = MINUTES * timeoutMinutes;

        final String tokenFileName = config.form_token_file();
        final File tokenFile = getTokenFile(tokenFileName, componentContext.getBundleContext());
        final boolean fastSeed = config.form_token_fastseed();
        log.info("Storing tokens in {}", tokenFile.getAbsolutePath());
        this.tokenStore = new TokenStore(tokenFile, sessionTimeout, fastSeed);

        this.loginModule = null;
        if (!jaasHelper.enabled()) {
            try {
                this.loginModule = FormLoginModulePlugin.register(this, componentContext.getBundleContext());
            } catch (Throwable t) {
                log.info(
                        "Cannot register FormLoginModulePlugin. This is expected if Sling LoginModulePlugin services are not supported");
                log.debug("dump", t);
            }
        }

        this.includeLoginForm = config.useInclude();

        this.loginAfterExpire = config.form_onexpire_login();
        
        this.preferReasonCode = config.preferReasonCode();
    }

    @Deactivate
    protected void deactivate() {
        if (jaasHelper != null) {
            jaasHelper.close();
            jaasHelper = null;
        }

        if (loginModule != null) {
            loginModule.unregister();
            loginModule = null;
        }
    }

    /**
     * Returns an absolute file indicating the file to use to persist the security
     * tokens.
     * <p>
     * This method is not part of the API of this class and is package private to
     * enable unit tests.
     *
     * @param tokenFileName
     *            The configured file name, must not be null
     * @param bundleContext
     *            The BundleContext to use to make an relative file absolute
     * @return The absolute file
     */
    File getTokenFile(final String tokenFileName, final BundleContext bundleContext) {
        File tokenFile = new File(tokenFileName);
        if (tokenFile.isAbsolute()) {
            return tokenFile;
        }

        tokenFile = bundleContext.getDataFile(tokenFileName);
        if (tokenFile == null) {
            final String slingHome = bundleContext.getProperty("sling.home");
            if (slingHome != null) {
                tokenFile = new File(slingHome, tokenFileName);
            } else {
                tokenFile = new File(tokenFileName);
            }
        }

        return tokenFile.getAbsoluteFile();
    }

    /**
     * Returns the user id from the authentication data. If the authentication data
     * is a non-<code>null</code> value with 3 fields separated by an @ sign, the
     * value of the third field is returned. Otherwise <code>null</code> is
     * returned.
     * <p>
     * This method is not part of the API of this class and is package private to
     * enable unit tests.
     *
     * @param authData
     * @return
     */
    String getUserId(final String authData) {
        if (authData != null) {
            String[] parts = TokenStore.split(authData);
            if (parts.length == 3) {
                return parts[2];
            }
        }
        return null;
    }

    /**
     * Refresh the cookie periodically.
     *
     * @param sessionTimeout
     *            time to live for the session
     * @return true or false
     */
    private boolean needsRefresh(final String authData, final long sessionTimeout) {
        boolean updateCookie = false;
        if (authData == null) {
            updateCookie = true;
        } else {
            String[] parts = TokenStore.split(authData);
            if (parts.length == 3) {
                long cookieTime = Long.parseLong(parts[1].substring(1));
                if (System.currentTimeMillis() + (sessionTimeout / 2) > cookieTime) {
                    updateCookie = true;
                }
            }
        }
        return updateCookie;
    }

    /**
     * The <code>AuthenticationStorage</code> interface abstracts the API required
     * to store the authentication data in an HTTP cookie or in an HTTP Session. The
     * concrete class -- {@link CookieStorage} or {@link SessionStorage} -- is
     * selected using the {@link FormAuthenticationHandler#PAR_AUTH_STORAGE}
     * configuration parameter, {@link CookieStorage} by default.
     */
    private static interface AuthenticationStorage {
        String extractAuthenticationInfo(HttpServletRequest request);

        void set(HttpServletRequest request, HttpServletResponse response, String authData, AuthenticationInfo info);

        void clear(HttpServletRequest request, HttpServletResponse response);
    }

    /**
     * The <code>CookieStorage</code> class supports storing the authentication data
     * in an HTTP Cookie.
     */
    private static class CookieStorage implements AuthenticationStorage {
        private final Logger log = LoggerFactory.getLogger(getClass());

        private final String cookieName;
        private final String domainCookieName;
        private final String defaultCookieDomain;

        public CookieStorage(final String cookieName, final String defaultCookieDomain) {
            this.cookieName = cookieName;
            this.domainCookieName = cookieName + "." + COOKIE_DOMAIN;
            this.defaultCookieDomain = defaultCookieDomain;
        }

        @Override
        public String extractAuthenticationInfo(HttpServletRequest request) {
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (this.cookieName.equals(cookie.getName())) {
                        // found the cookie, so try to extract the credentials
                        // from it and reverse the base64 encoding
                        String value = cookie.getValue();
                        if (value.length() > 0) {
                            return new String(Base64.decodeBase64(value), StandardCharsets.UTF_8);
                        }
                    }
                }
            }

            return null;
        }

        @Override
        public void set(HttpServletRequest request, HttpServletResponse response, String authData,
                AuthenticationInfo info) {
            // base64 encode to handle any special characters
            String cookieValue = Base64.encodeBase64URLSafeString(authData.getBytes(StandardCharsets.UTF_8));

            // send the cookie to the response
            String cookieDomain = (String) info.get(COOKIE_DOMAIN);
            if (cookieDomain == null || cookieDomain.length() == 0) {
                cookieDomain = defaultCookieDomain;
            }

            if (!isValidCookieDomain(request, cookieDomain)) {
                log.warn("Sending formauth cookies without a cookie domain because the configured value is invalid for the request");
                cookieDomain = null;
            }

            setCookie(request, response, this.cookieName, cookieValue, -1, cookieDomain);

            // send the cookie domain cookie if domain is not null
            if (cookieDomain != null) {
                setCookie(request, response, this.domainCookieName, cookieDomain, -1, cookieDomain);
            }
        }

        @Override
        public void clear(HttpServletRequest request, HttpServletResponse response) {
            Cookie oldCookie = null;
            String oldCookieDomain = null;
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (this.cookieName.equals(cookie.getName())) {
                        // found the cookie
                        oldCookie = cookie;
                    } else if (this.domainCookieName.equals(cookie.getName())) {
                        oldCookieDomain = cookie.getValue();
                        if (oldCookieDomain.length() == 0) {
                            oldCookieDomain = null;
                        }
                    }
                }
            }

            if (!isValidCookieDomain(request, oldCookieDomain)) {
                log.warn("The client supplied domain cookie value was invalid, will try clearing the cookies with the default cookie domain instead");
                oldCookieDomain = defaultCookieDomain;
            }

            // remove the old cookie from the client
            if (oldCookie != null) {
                setCookie(request, response, this.cookieName, "", 0, oldCookieDomain);
                if (oldCookieDomain != null && oldCookieDomain.length() > 0) {
                    setCookie(request, response, this.domainCookieName, "", 0, oldCookieDomain);
                }
            }
        }

        /**
         * Validates that the cookie domain is valid for the request host
         * 
         * @param request the current request
         * @param cookieDomain the candidate cookie domain value
         * @return true if valid, false otherwise
         */
        private boolean isValidCookieDomain(HttpServletRequest request, String cookieDomain) {
            boolean valid = false;
            if (cookieDomain == null) {
                valid = true;
            } else {
                // a valid cookie domain must be a suffix of the host
                String host = request.getServerName();
                if (host.endsWith(cookieDomain)) {
                    valid = true;
                }
            }
            return valid;
        }

        private void setCookie(final HttpServletRequest request, final HttpServletResponse response, final String name,
                final String value, final int age, final String domain) {

            final String ctxPath = request.getContextPath();
            final String cookiePath = (ctxPath == null || ctxPath.length() == 0) ? "/" : ctxPath;

            Cookie c = new Cookie(name, value);
            c.setPath(cookiePath);
            c.setHttpOnly(false); // don't allow JS access

            // set the cookie domain if so configured
            if (domain != null) {
                c.setDomain(domain);
            }

            // Only set the Max-Age attribute to remove the cookie
            if (age >= 0) {
                c.setMaxAge(age);
            }

            // ensure the cookie is secured if this is an https request
            c.setSecure(request.isSecure());

            response.addCookie(c);
        }
    }

    /**
     * The <code>SessionStorage</code> class provides support to store the
     * authentication data in an HTTP Session.
     */
    private static class SessionStorage implements AuthenticationStorage {
        private final String sessionAttributeName;

        SessionStorage(final String sessionAttributeName) {
            this.sessionAttributeName = sessionAttributeName;
        }

        @Override
        public String extractAuthenticationInfo(HttpServletRequest request) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                Object attribute = session.getAttribute(sessionAttributeName);
                if (attribute instanceof String) {
                    return (String) attribute;
                }
            }
            return null;
        }

        @Override
        public void set(HttpServletRequest request, HttpServletResponse response, String authData,
                AuthenticationInfo info) {
            // store the auth hash as a session attribute
            HttpSession session = request.getSession();
            session.setAttribute(sessionAttributeName, authData);
        }

        @Override
        public void clear(HttpServletRequest request, HttpServletResponse response) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.removeAttribute(sessionAttributeName);
            }
        }

    }
}
