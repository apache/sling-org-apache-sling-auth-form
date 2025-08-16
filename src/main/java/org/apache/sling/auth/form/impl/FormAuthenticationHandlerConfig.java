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

import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.AttributeType;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.osgi.service.metatype.annotations.Option;

/**
 * The configuration for the <code>FormAuthenticationHandler</code>
 *
 * @see org.apache.sling.auth.form.impl.FormAuthenticationHandler
 */
@ObjectClassDefinition(name = "%auth.form.name", description = "%auth.form.description")
public @interface FormAuthenticationHandlerConfig {

    public static final int DEFAULT_JAAS_RANKING = 1000;
    public static final String AUTH_STORAGE_SESSION_ATTRIBUTE = "session";
    public static final String DEEFAULT_JAAS_CONTROL_FLAG = "sufficient";
    public static final String DEFAULT_AUTH_CREDENTIALS_NAME = "sling.formauth";
    public static final String DEFAULT_AUTH_FORM_STORAGE = "cookie";
    public static final int DEFAULT_AUTH_TIMEOUT = 30;
    public static final String DEFAULT_JAAS_REALM_NAME = "jackrabbit.oak";
    public static final String DEFAULT_FORM_TOKEN_FILE = "cookie-tokens.bin";

    @AttributeDefinition(name = "%authName.name", description = "%authName.description")
    String form_auth_name() default DEFAULT_AUTH_CREDENTIALS_NAME; // NOSONAR

    @AttributeDefinition(
            options = {
                @Option(label = "Cookie", value = DEFAULT_AUTH_FORM_STORAGE),
                @Option(label = "Session Attribute", value = AUTH_STORAGE_SESSION_ATTRIBUTE)
            },
            name = "%authStorage.name",
            description = "%authStorage.description")
    String form_auth_storage() default DEFAULT_AUTH_FORM_STORAGE; // NOSONAR

    @AttributeDefinition(
            type = AttributeType.INTEGER,
            name = "%authTimeout.name",
            description = "%authTimeout.description")
    int form_auth_timeout() default DEFAULT_AUTH_TIMEOUT; // NOSONAR

    @AttributeDefinition(name = "%credentialsName.name", description = "%credentialsName.description")
    String form_credentials_name() default DEFAULT_AUTH_CREDENTIALS_NAME; // NOSONAR

    @AttributeDefinition(name = "%defaultCookieDomain.name", description = "%defaultCookieDomain.description")
    String form_default_cookie_domain() default ""; // NOSONAR

    @AttributeDefinition(name = "%loginForm.name", description = "%loginForm.description")
    String form_login_form() default AuthenticationFormServlet.SERVLET_PATH; // NOSONAR

    @AttributeDefinition(name = "%onexpireLogin.name", description = "%onexpireLogin.description")
    boolean form_onexpire_login() default false; // NOSONAR

    @AttributeDefinition(
            type = AttributeType.BOOLEAN,
            name = "%tokenFileFastseed.name",
            description = "%tokenFileFastseed.description")
    boolean form_token_fastseed() default false; // NOSONAR

    @AttributeDefinition(name = "%tokenFile.name", description = "%tokenFile.description")
    String form_token_file() default DEFAULT_FORM_TOKEN_FILE; // NOSONAR

    @AttributeDefinition(
            options = {
                @Option(label = "Optional", value = "optional"),
                @Option(label = "Required", value = "required"),
                @Option(label = "Requisite", value = "requisite"),
                @Option(label = "Sufficient", value = DEEFAULT_JAAS_CONTROL_FLAG)
            },
            name = "%jaasControlFlag.name",
            description = "%jaasControlFlag.description")
    String jaas_controlFlag() default DEEFAULT_JAAS_CONTROL_FLAG; // NOSONAR

    @AttributeDefinition(
            type = AttributeType.INTEGER,
            name = "%jaasRanking.name",
            description = "%jaasRanking.description")
    int jaas_ranking() default DEFAULT_JAAS_RANKING; // NOSONAR

    @AttributeDefinition(name = "%jaasRealm.name", description = "%jaasRealm.description")
    String jaas_realmName() default DEFAULT_JAAS_REALM_NAME; // NOSONAR

    @AttributeDefinition(cardinality = Integer.MAX_VALUE, name = "%path.name", description = "%path.description")
    String[] path() default {"/"};

    @AttributeDefinition(
            type = AttributeType.INTEGER,
            name = "%service.ranking.name",
            description = "%service.ranking.description")
    int service_ranking() default 0; // NOSONAR

    @AttributeDefinition(
            type = AttributeType.BOOLEAN,
            name = "%useInclude.name",
            description = "%useInclude.description")
    boolean useInclude() default false;

    @AttributeDefinition(
            type = AttributeType.BOOLEAN,
            name = "%preferReasonCode.name",
            description = "%preferReasonCode.description")
    boolean preferReasonCode() default false;
}
