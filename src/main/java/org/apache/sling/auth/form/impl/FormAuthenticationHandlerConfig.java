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

	public static final String AUTH_STORAGE_SESSION_ATTRIBUTE = "session";
	public static final int DEFAULT_AUTH_TIMEOUT = 30;

	@AttributeDefinition(defaultValue = "sling.formauth", name = "%authName.name", description = "%authName.description")
	String form_auth_name();

	@AttributeDefinition(defaultValue = "cookie", options = { @Option(label = "Cookie", value = "cookie"),
			@Option(label = "Session Attribute", value = AUTH_STORAGE_SESSION_ATTRIBUTE) }, name = "%authStorage.name", description = "%authStorage.description")
	String form_auth_storage();

	@AttributeDefinition(defaultValue = "30", type = AttributeType.INTEGER, name = "%authTimeout.name", description = "%authTimeout.description")
	int form_auth_timeout();

	@AttributeDefinition(defaultValue = "sling.formauth", name = "%credentialsName.name", description = "%credentialsName.description")
	String form_credentials_name();

	@AttributeDefinition(name = "%defaultCookieDomain.name", description = "%defaultCookieDomain.description")
	String form_default_cookie_domain();

	@AttributeDefinition(defaultValue = AuthenticationFormServlet.SERVLET_PATH, name = "%loginForm.name", description = "%loginForm.description")
	String form_login_form();

	@AttributeDefinition(defaultValue = "false", type = AttributeType.BOOLEAN, name = "%onexpireLogin.name", description = "%onexpireLogin.description")
	boolean form_onexpire_login();

	@AttributeDefinition(defaultValue = "false", type = AttributeType.BOOLEAN, name = "%tokenFileFastseed.name", description = "%tokenFileFastseed.description")
	boolean form_token_fastseed();

	@AttributeDefinition(defaultValue = "cookie-tokens.bin", name = "%tokenFile.name", description = "%tokenFile.description")
	String form_token_file();

	@AttributeDefinition(defaultValue = "sufficient", options = { @Option(label = "Optional", value = "optional"),
			@Option(label = "Required", value = "required"), @Option(label = "Requisite", value = "requisite"),
			@Option(label = "Sufficient", value = "sufficient") }, name = "%jaasControlFlag.name", description = "%jaasControlFlag.description")
	String jaas_controlFlag();

	@AttributeDefinition(defaultValue = "1000", type = AttributeType.INTEGER, name = "%jaasRanking.name", description = "%jaasRanking.description")
	int jaas_ranking();

	@AttributeDefinition(defaultValue = "jackrabbit.oak", name = "%jaasRealm.name", description = "%jaasRealm.description")
	String jaas_realmName();

	@AttributeDefinition(defaultValue = {
			"/" }, cardinality = Integer.MAX_VALUE, name = "%path.name", description = "%path.description")
	String[] path();

	@AttributeDefinition(defaultValue = "0", type = AttributeType.INTEGER, name = "%service.ranking.name", description = "%service.ranking.description")
	int service_ranking();

	@AttributeDefinition(defaultValue = "false", type = AttributeType.BOOLEAN, name = "%useInclude.name", description = "%useInclude.description")
	boolean useInclude();

}
