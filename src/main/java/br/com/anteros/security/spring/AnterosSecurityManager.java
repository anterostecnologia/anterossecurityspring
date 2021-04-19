/*******************************************************************************
 * Copyright 2012 Anteros Tecnologia
 *  
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *  
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package br.com.anteros.security.spring;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.context.WebApplicationContext;

import br.com.anteros.core.log.Logger;
import br.com.anteros.core.log.LoggerProvider;
import br.com.anteros.core.scanner.ClassFilter;
import br.com.anteros.core.scanner.ClassPathScanner;
import br.com.anteros.core.utils.ObjectUtils;
import br.com.anteros.core.utils.ReflectionUtils;
import br.com.anteros.core.utils.StringUtils;
import br.com.anteros.security.store.SecurityDataStore;
import br.com.anteros.security.store.domain.IAction;
import br.com.anteros.security.store.domain.IResource;
import br.com.anteros.security.store.domain.ISystem;
import br.com.anteros.security.store.domain.IUser;

/**
 * 
 * @author Edson Martins edsonmartins2005@gmail.com
 *
 */
@Component("authenticationManager")
@ComponentScan("br.com.anteros.security.spring")
public class AnterosSecurityManager implements AuthenticationProvider, InitializingBean, AuthenticationManager,
		UserDetailsService, UserDetailsManager, ClientRegistrationService, ClientDetailsService {

	@Autowired
	private PasswordEncoder userPasswordEncoder;

	@Autowired
	private SecurityDataStore securityDataStore;

	protected String packageToScanSecurity;
	protected String systemName;
	protected String description;
	protected String version;
	protected boolean adminNeedsPermission = true;

	private static Logger LOG = LoggerProvider.getInstance().getLogger(AnterosSecurityManager.class.getName());
	private boolean initialized = false;

	private Map<String, AnterosSecurityUser> cacheUsers = new HashMap<String, AnterosSecurityUser>();

	@Autowired
	protected WebApplicationContext context;

	private ResourceServerTokenServices tokenServices;

	public ResourceServerTokenServices getTokenServices() {
		return tokenServices;
	}

	public void setTokenServices(ResourceServerTokenServices tokenServices) {
		this.tokenServices = tokenServices;
	}

	public String getResourceId() {
		return resourceId;
	}

	public void setResourceId(String resourceId) {
		this.resourceId = resourceId;
	}

	private String resourceId;

	public AnterosSecurityManager() {
		super();
	}

	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		String username = "";
		if (authentication == null) {
			throw new InvalidTokenException("Invalid token (token not found)");
		}

		if (tokenServices != null && ObjectUtils.isEmpty(authentication.getCredentials())) {
			String token = (String) authentication.getPrincipal();
			OAuth2Authentication auth = tokenServices.loadAuthentication(token);
			if (auth == null) {
				throw new InvalidTokenException("Invalid token: " + token);
			}

			Collection<String> resourceIds = auth.getOAuth2Request().getResourceIds();
			if (resourceId != null && resourceIds != null && !resourceIds.isEmpty()
					&& !resourceIds.contains(resourceId)) {
				throw new OAuth2AccessDeniedException(
						"Invalid token does not contain resource id (" + resourceId + ")");
			}

			if (authentication.getDetails() instanceof OAuth2AuthenticationDetails) {
				OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) authentication.getDetails();
				// Guard against a cached copy of the same details
				if (!details.equals(auth.getDetails())) {
					// Preserve the authentication details from the one loaded by token services
					details.setDecodedDetails(auth.getDetails());
				}
			}
			auth.setDetails(authentication.getDetails());
			auth.setAuthenticated(true);

			AnterosSecurityUser user = null;
			if (auth.getPrincipal() instanceof AnterosSecurityUser) {
				username = ((AnterosSecurityUser) auth.getPrincipal()).getUsername();
			} else {
				username = auth.getPrincipal() + "";
			}
			user = cacheUsers.get(username);
			if (user == null) {
				IUser userDomain = securityDataStore.getUserByUserNameWithPassword(username);
				if (userDomain != null) {
					user = new AnterosSecurityUser(userDomain, systemName);
				}
				if (userDomain.isBlockedAccount()) {
					throw new UserBlockedAccountException("Blocked account " + user.getUsername());
				}
				if (userDomain.isInactiveAccount()) {
					throw new UserInactiveAccountException("Inactive account " + user.getUsername());
				}
				
			}
			if (user == null) {
				throw new BadCredentialsException("Username not found.");
			}
			if (authentication.getCredentials() == null) {
				LOG.debug("Authentication failed: no credentials provided");
				throw new BadCredentialsException("Bad credentials " + user.getUsername());
			}

			((AnterosSecurityUser) user).setSystemName(systemName);
			((AnterosSecurityUser) user).setVersion(version);
			((AnterosSecurityUser) user).setAdminNeedsPermission(adminNeedsPermission);

			Collection<GrantedAuthority> authorities = (Collection<GrantedAuthority>) user.getAuthorities();

			return new AnterosSecurityOAuth2Authentication(user, auth, authorities);

		} else {
			LOG.debug("Authenticate user " + authentication);
			username = authentication.getName();
			AnterosSecurityUser user = cacheUsers.get(username);
			if (user == null) {
				IUser userDomain = securityDataStore.getUserByUserNameWithPassword(username);
				if (userDomain != null) {
					user = new AnterosSecurityUser(userDomain, systemName);
				}
			}
			if (user == null) {
				throw new BadCredentialsException("Username not found.");
			}
			if (authentication.getCredentials() == null) {
				LOG.debug("Authentication failed: no credentials provided");
				throw new BadCredentialsException("Bad credentials " + user.getUsername());
			}

			String presentedPassword = authentication.getCredentials().toString();

			if (!user.getPassword().equals(presentedPassword)) {
				LOG.debug("Authentication failed: password does not match stored value");
				throw new BadCredentialsException("Bad credentials " + user.getUsername());
			}

			((AnterosSecurityUser) user).setSystemName(systemName);
			((AnterosSecurityUser) user).setVersion(version);
			((AnterosSecurityUser) user).setAdminNeedsPermission(adminNeedsPermission);

			Collection<? extends GrantedAuthority> authorities = user.getAuthorities();

			return new AnterosSecurityAuthenticationToken(user, authentication.getCredentials(), authorities);
		}
	}

	private void checkClientDetails(OAuth2Authentication auth) {
		ClientDetails client;
		try {
			client = this.loadClientByClientId(auth.getOAuth2Request().getClientId());
		} catch (ClientRegistrationException e) {
			throw new OAuth2AccessDeniedException("Invalid token contains invalid client id");
		}
		Set<String> allowed = client.getScope();
		for (String scope : auth.getOAuth2Request().getScope()) {
			if (!allowed.contains(scope)) {
				throw new OAuth2AccessDeniedException(
						"Invalid token contains disallowed scope (" + scope + ") for this client");
			}
		}
	}

	public boolean supports(Class<?> authentication) {
		return true;
	}

	public void configure() throws Exception {
		afterPropertiesSet();
	}

	public void afterPropertiesSet() throws Exception {
		if (StringUtils.isNotEmpty(systemName) && StringUtils.isNotEmpty(version)
				&& StringUtils.isNotEmpty(packageToScanSecurity) && (!initialized)) {

			securityDataStore.initializeCurrentSession();

			scanPackages();
			initialized = true;
			
			securityDataStore.clearCurrentSession();
		}
	}

	protected void scanPackages() {
		if ((packageToScanSecurity != null) && (!"".equals(packageToScanSecurity))) {
			String[] packages = StringUtils.tokenizeToStringArray(packageToScanSecurity, ", ;");
			List<Class<?>> scanClasses = ClassPathScanner
					.scanClasses(new ClassFilter().packages(packages).annotation(ResourceSecured.class));

			loadSecuredResourcesAndActions(scanClasses);
		}

	}

	protected void loadSecuredResourcesAndActions(List<Class<?>> classes) {
		try {
			IAction action = null;
			IResource resource = null;
			ISystem system = securityDataStore.getSystemByName(systemName);
			if (system == null) {
				system = securityDataStore.addSystem(systemName, description);
			}
			for (Class<?> cl : classes) {
				if (cl.isAnnotationPresent(ResourceSecured.class)) {
					ResourceSecured resourceSecured = cl.getAnnotation(ResourceSecured.class);

					resource = securityDataStore.getResourceByName(systemName, resourceSecured.resourceName());
					if (resource == null) {
						resource = securityDataStore.addResource(system, resourceSecured.resourceName(),
								resourceSecured.description());
						securityDataStore.refreshResource(resource);
					}

					/*
					 * Verifica ações declaradas e não salvas ou inativas
					 */
					Method[] methods = ReflectionUtils.getAllDeclaredMethods(cl);

					for (Method method : methods) {
						if (method.isAnnotationPresent(ActionSecured.class)) {
							boolean found = false;
							boolean active = false;
							action = null;
							ActionSecured actionSecured = method.getAnnotation(ActionSecured.class);
							for (IAction act : resource.getActionList()) {
								if (act.getActionName().equalsIgnoreCase(actionSecured.actionName())) {
									found = true;
									active = act.isActionActive();
									action = act;
									break;
								}
							}

							if (!found) {
								action = securityDataStore.addAction(system, resource, actionSecured.actionName(),
										actionSecured.category(), actionSecured.description(), version);
								resource.addAction(action);
							} else {
								if (action != null) {
									boolean save = false;
									if (!active) {
										action.setActiveAction(true);
										save = true;
									}
									if (!(action.getCategory().equalsIgnoreCase(actionSecured.category()))) {
										action.setCategory(actionSecured.category());
										save = true;
									}
									if (save) {
										securityDataStore.saveAction(action);
									}
								}
							}
						}
					}

					/*
					 * Verifica ações salvas e não existentes mais no recurso.
					 */
					resource = securityDataStore.refreshResource(resource);

					for (IAction act : resource.getActionList()) {
						boolean found = false;
						for (Method method : methods) {
							if (method.isAnnotationPresent(ActionSecured.class)) {
								ActionSecured actionSecured = method.getAnnotation(ActionSecured.class);
								if (actionSecured.actionName().equalsIgnoreCase(act.getActionName())) {
									found = true;
									break;
								}
							}
						}

						if (!found) {
							if (act.getVersion().compareTo(version) < 0) {
								securityDataStore.removeActionByAllUsers(act);
							}
						}
					}

				}
			}
		} catch (Exception e) {
			throw new AnterosSecurityException(e);
		}

	}

	public String getPackageToScanSecurity() {
		return packageToScanSecurity;
	}

	public AnterosSecurityManager setPackageToScanSecurity(String packageToScanSecurity) throws Exception {
		this.packageToScanSecurity = packageToScanSecurity;
		configure();
		return this;
	}

	public String getSystemName() {
		return systemName;
	}

	public AnterosSecurityManager setSystemName(String systemName) throws Exception {
		this.systemName = systemName;
		configure();
		return this;
	}

	public String getDescription() {
		return description;
	}

	public AnterosSecurityManager setDescription(String description) throws Exception {
		this.description = description;
		configure();
		return this;
	}

	public String getVersion() {
		return version;
	}

	public AnterosSecurityManager setVersion(String version) throws Exception {
		this.version = version;
		configure();
		return this;
	}

	public PasswordEncoder getPasswordEncoder() {
		return userPasswordEncoder;
	}

	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		this.userPasswordEncoder = passwordEncoder;
	}

	public boolean isAdminNeedsPermission() {
		return adminNeedsPermission;
	}

	public AnterosSecurityManager setAdminNeedsPermission(boolean adminNeedsPermission) throws Exception {
		this.adminNeedsPermission = adminNeedsPermission;
		return this;
	}

	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		IUser user = securityDataStore.getUserByUserName(username);
		if (user == null)
			return null;
		return new AnterosSecurityUser(user);
	}

	public UserDetails loadUserByUsername(String username, String systemName) throws UsernameNotFoundException {
		IUser user = securityDataStore.getUserByUserName(username);
		if (user == null)
			return null;
		return new AnterosSecurityUser(user, systemName);
	}

	@Override
	public void createUser(UserDetails user) {
		throw new RuntimeException("não implementado ainda createUser");

	}

	@Override
	public void updateUser(UserDetails user) {
		throw new RuntimeException("não implementado ainda updateUser");

	}

	@Override
	public void deleteUser(String username) {
		throw new RuntimeException("não implementado ainda deleteUser");

	}

	@Override
	public void changePassword(String oldPassword, String newPassword) {
		throw new RuntimeException("não implementado ainda changePassword");

	}

	@Override
	public boolean userExists(String username) {
		throw new RuntimeException("não implementado ainda userExists");
	}

	@Override
	public void addClientDetails(ClientDetails clientDetails) throws ClientAlreadyExistsException {
		securityDataStore.addClientDetails(clientDetails);
	}

	@Override
	public void updateClientDetails(ClientDetails clientDetails) throws NoSuchClientException {
		securityDataStore.updateClientDetails(clientDetails);
	}

	@Override
	public void updateClientSecret(String clientId, String secret) throws NoSuchClientException {
		securityDataStore.updateClientSecret(clientId, secret);
	}

	@Override
	public void removeClientDetails(String clientId) throws NoSuchClientException {
		securityDataStore.removeClientDetails(clientId);
	}

	@Override
	public List<ClientDetails> listClientDetails() {
		return securityDataStore.listClientDetails();
	}

	@Override
	public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
		return securityDataStore.loadClientByClientId(clientId);
	}

}
