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

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.dao.SaltSource;
import org.springframework.security.authentication.encoding.PasswordEncoder;
import org.springframework.security.authentication.encoding.PlaintextPasswordEncoder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;

import br.com.anteros.core.log.Logger;
import br.com.anteros.core.log.LoggerProvider;
import br.com.anteros.core.scanner.ClassFilter;
import br.com.anteros.core.scanner.ClassPathScanner;
import br.com.anteros.core.utils.ReflectionUtils;
import br.com.anteros.core.utils.StringUtils;
import br.com.anteros.security.model.Action;
import br.com.anteros.security.model.Resource;

/**
 * 
 * @author Edson Martins edsonmartins2005@gmail.com
 *
 */
@Component("anterosSecurityManager")
@ComponentScan("br.com.anteros.security.spring")
@SuppressWarnings("deprecation")
public class AnterosSecurityManager implements AuthenticationProvider, InitializingBean {

	protected String packageToScanSecurity;
	protected String systemName;
	protected String description;
	protected String version;
	protected boolean adminNeedsPermission = true;
	private PasswordEncoder passwordEncoder = new PlaintextPasswordEncoder();
	private SaltSource saltSource;
	private static Logger LOG = LoggerProvider.getInstance().getLogger(AnterosSecurityManager.class.getName());
	private boolean initialized = false;

	private Map<String, AnterosSecurityUser> cacheUsers = new HashMap<String, AnterosSecurityUser>();

	@Autowired
	protected WebApplicationContext context;

	public AnterosSecurityManager() {
		super();
	}

	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		LOG.debug("Authenticate user " + authentication);
		String username = authentication.getName();
		AnterosSecurityUser user = cacheUsers.get(username);
		if (user == null) {
			AnterosSecurityService anterosSecurityService = (AnterosSecurityService) context.getBean("anterosSecurityService");
			user = (AnterosSecurityUser) anterosSecurityService.loadUserByUsername(username, systemName);
		}
		if (user == null) {
			throw new BadCredentialsException("Username not found.");
		}
		if (authentication.getCredentials() == null) {
			LOG.debug("Authentication failed: no credentials provided");
			throw new BadCredentialsException("Bad credentials " + user.getUsername());
		}

		Object salt = null;

		if (this.saltSource != null) {
			salt = this.saltSource.getSalt(user);
		}

		String presentedPassword = authentication.getCredentials().toString();

		if (!passwordEncoder.isPasswordValid(user.getPassword(), presentedPassword, salt)) {
			LOG.debug("Authentication failed: password does not match stored value");
			throw new BadCredentialsException("Bad credentials " + user.getUsername());
		}

		((AnterosSecurityUser) user).setSystemName(systemName);
		((AnterosSecurityUser) user).setVersion(version);
		((AnterosSecurityUser) user).setAdminNeedsPermission(adminNeedsPermission);

		Collection<? extends GrantedAuthority> authorities = user.getAuthorities();

		return new AnterosSecurityAuthenticationToken(user, authentication.getCredentials(), authorities);
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
			scanPackages();
			initialized = true;
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
			AnterosSecurityService anterosSecurityService = (AnterosSecurityService) context.getBean("anterosSecurityService");
			Action action = null;
			Resource resource = null;
			br.com.anteros.security.model.System system = anterosSecurityService.getSystemByName(systemName);
			if (system == null) {
				system = anterosSecurityService.addSystem(systemName, description);
			}
			for (Class<?> cl : classes) {
				if (cl.isAnnotationPresent(ResourceSecured.class)) {
					ResourceSecured resourceSecured = cl.getAnnotation(ResourceSecured.class);

					resource = anterosSecurityService.getResourceByName(systemName, resourceSecured.resourceName());
					if (resource == null) {
						resource = anterosSecurityService.addResource(system, resourceSecured.resourceName(),
								resourceSecured.description());
						anterosSecurityService.refreshResource(resource);
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
							for (Action act : resource.getAcoes()) {
								if (act.getNome().equalsIgnoreCase(actionSecured.actionName())) {
									found = true;
									active = act.getAtiva();
									action = act;
									break;
								}
							}

							if (!found) {
								action = anterosSecurityService.addAction(system, resource, actionSecured.actionName(),
										actionSecured.category(), actionSecured.description(), version);
							} else {
								if (action != null) {
									boolean save = false;
									if (!active) {
										action.setAtiva(true);
										save = true;
									}
									if (!(action.getCategoria().equalsIgnoreCase(actionSecured.category()))) {
										action.setCategoria(actionSecured.category());
										save = true;
									}
									if (save) {
										anterosSecurityService.saveAction(action);
									}
								}
							}
						}
					}

					/*
					 * Verifica ações salvas e não existentes mais no recurso.
					 */
					resource = anterosSecurityService.refreshResource(resource);

					for (Action act : resource.getAcoes()) {
						boolean found = false;
						for (Method method : methods) {
							if (method.isAnnotationPresent(ActionSecured.class)) {
								ActionSecured actionSecured = method.getAnnotation(ActionSecured.class);
								if (actionSecured.actionName().equalsIgnoreCase(act.getNome())) {
									found = true;
									break;
								}
							}
						}

						if (!found) {
							if (act.getVersao().compareTo(version) < 0) {
								anterosSecurityService.removeActionByAllUsers(act);
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
		return this;
	}

	public String getSystemName() {
		return systemName;
	}

	public AnterosSecurityManager setSystemName(String systemName) throws Exception {
		this.systemName = systemName;
		return this;
	}

	public String getDescription() {
		return description;
	}

	public AnterosSecurityManager setDescription(String description) throws Exception {
		this.description = description;
		return this;
	}

	public String getVersion() {
		return version;
	}

	public AnterosSecurityManager setVersion(String version) throws Exception {
		this.version = version;
		return this;
	}

	public PasswordEncoder getPasswordEncoder() {
		return passwordEncoder;
	}

	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	public SaltSource getSaltSource() {
		return saltSource;
	}

	public void setSaltSource(SaltSource saltSource) {
		this.saltSource = saltSource;
	}

	public boolean isAdminNeedsPermission() {
		return adminNeedsPermission;
	}

	public AnterosSecurityManager setAdminNeedsPermission(boolean adminNeedsPermission) throws Exception {
		this.adminNeedsPermission = adminNeedsPermission;
		return this;
	}

}
