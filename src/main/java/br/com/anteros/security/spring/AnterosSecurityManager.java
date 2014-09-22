package br.com.anteros.security.spring;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.List;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.dao.SaltSource;
import org.springframework.security.authentication.encoding.Md5PasswordEncoder;
import org.springframework.security.authentication.encoding.PasswordEncoder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import br.com.anteros.core.log.Logger;
import br.com.anteros.core.log.LoggerProvider;
import br.com.anteros.core.scanner.ClassFilter;
import br.com.anteros.core.scanner.ClassPathScanner;
import br.com.anteros.core.utils.Assert;
import br.com.anteros.core.utils.ReflectionUtils;
import br.com.anteros.core.utils.StringUtils;
import br.com.anteros.security.model.Action;
import br.com.anteros.security.model.Resource;
import br.com.anteros.security.model.System;

@Component
@ComponentScan("br.com.anteros.security.spring")
@SuppressWarnings("deprecation")
public class AnterosSecurityManager implements AuthenticationProvider, InitializingBean {

	protected String packageToScanSecurity;
	protected String systemName;
	protected String description;
	protected String version;
	private PasswordEncoder passwordEncoder = new Md5PasswordEncoder();
	private SaltSource saltSource;
	private static Logger LOG = LoggerProvider.getInstance().getLogger(AnterosSecurityManager.class.getName());

	@Autowired
	protected AnterosSecurityService anterosSecurityService;

	
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String username = authentication.getName();
		UserDetails user = anterosSecurityService.loadUserByUsername(username);
		if (user == null) {
			throw new BadCredentialsException("Username not found.");
		}
		if (authentication.getCredentials() == null) {
			LOG.debug("Authentication failed: no credentials provided");
			throw new BadCredentialsException("Bad credentials", user);
		}
	

		Object salt = null;

		if (this.saltSource != null) {
			salt = this.saltSource.getSalt(user);
		}

		String presentedPassword = authentication.getCredentials().toString();

		if (!passwordEncoder.isPasswordValid(user.getPassword(), presentedPassword, salt)) {
			LOG.debug("Authentication failed: password does not match stored value");
			throw new BadCredentialsException("Bad credentials", user);
		}

		((AnterosSecurityUser) user).setSystemName(systemName);
		((AnterosSecurityUser) user).setVersion(version);

		Collection<? extends GrantedAuthority> authorities = user.getAuthorities();

		return new AnterosSecurityAuthenticationToken(user, authentication.getCredentials(), authorities);
	}

	public boolean supports(Class<?> authentication) {
		return true;
	}

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(systemName,
				"Para o correto funcionamento da segurança da aplicação é necessário informar o nome do sistema.");
		Assert.notNull(version,
				"Para o correto funcionamento da segurança da aplicação é necessário informar a versão do sistema.");
		scanPackages();
	}

	protected void scanPackages() {
		if ((packageToScanSecurity != null) && (!"".equals(packageToScanSecurity))) {
			String[] packages = StringUtils.tokenizeToStringArray(packageToScanSecurity, ", ;");
			List<Class<?>> scanClasses = ClassPathScanner.scanClasses(new ClassFilter().packages(packages).annotation(
					ResourceSecured.class));

			loadSecuredResourcesAndActions(scanClasses);
		}

	}

	protected void loadSecuredResourcesAndActions(List<Class<?>> classes) {
		try {
			System system = anterosSecurityService.getSystemByName(systemName);
			if (system == null) {
				system = anterosSecurityService.addSystem(systemName, description);
			}
			for (Class<?> cl : classes) {
				if (cl.isAnnotationPresent(ResourceSecured.class)) {
					ResourceSecured resourceSecured = cl.getAnnotation(ResourceSecured.class);

					Resource resource = anterosSecurityService.getResourceByName(systemName,
							resourceSecured.resourceName());
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
							Action action = null;
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
							if (act.getVersao().compareTo(version) <= 0) {
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

	public void setPackageToScanSecurity(String packageToScanSecurity) {
		this.packageToScanSecurity = packageToScanSecurity;
	}

	public String getSystemName() {
		return systemName;
	}

	public void setSystemName(String systemName) {
		this.systemName = systemName;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
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

}
