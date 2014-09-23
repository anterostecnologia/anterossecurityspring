package br.com.anteros.security.spring;

import java.lang.reflect.Method;
import java.util.Collection;

import org.springframework.aop.framework.ReflectiveMethodInvocation;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

@SuppressWarnings("rawtypes")
public class AnterosSecurityVoter implements AccessDecisionVoter {
	private static final String EMPTY_SYSTEM = "no_system";
	private static final String EMPTY_RESOURCE = "no_resource";
	private static final String EMPTY_ACTION = "no_action";

	private String rolePrefix = "ACT_";

	public String getActionPrefix() {
		return rolePrefix;
	}

	public void setRolePrefix(String rolePrefix) {
		this.rolePrefix = rolePrefix;
	}

	public boolean supports(ConfigAttribute config) {
		if ((config.getAttribute() != null) && config.getAttribute().startsWith(getActionPrefix())) {
			return true;
		} else {
			return false;
		}
	}

	public boolean supports(Class clazz) {
		return true;
	}

	public int vote(Authentication authentication, Object object, Collection attributes) {
		AnterosSecurityUser principal = (AnterosSecurityUser) authentication.getPrincipal();
		if (!principal.isAdminNeedsPermission()){
			return ACCESS_GRANTED;
		}
		
		int result = ACCESS_ABSTAIN;
		Collection<? extends GrantedAuthority> authorities = extractAuthorities(authentication);

		for (Object attribute : attributes) {
			ConfigAttribute configAttribute = (ConfigAttribute) attribute;
			if (this.supports(configAttribute)) {
				result = ACCESS_DENIED;

				
				String systemName = principal.getSystemName();
				String resourceName = EMPTY_RESOURCE;
				String actionName = configAttribute.getAttribute();
				boolean requiresAdmin = false;

				if (object instanceof ReflectiveMethodInvocation) {
					Method method = ((ReflectiveMethodInvocation) object).getMethod();
					Class<?> declaringClass = method.getDeclaringClass();
					if (declaringClass.isAnnotationPresent(ResourceSecured.class)) {
						ResourceSecured annotation = declaringClass
								.getAnnotation(ResourceSecured.class);
						resourceName = annotation.resourceName();
					}
					if (method.isAnnotationPresent(ActionSecured.class)) {
						ActionSecured secured = method.getAnnotation(ActionSecured.class);
						actionName = secured.actionName();
						requiresAdmin = secured.requiresAdmin();
					}
				}

				if (EMPTY_SYSTEM.equals(systemName) || EMPTY_RESOURCE.equals(resourceName)
						|| EMPTY_ACTION.equalsIgnoreCase(actionName)) {
					return ACCESS_DENIED;
				}

				if (requiresAdmin && (!principal.isAdmin()))
					return ACCESS_DENIED;

				for (GrantedAuthority authority : authorities) {
					if (authority instanceof AnterosSecurityGrantedAuthority) {
						if (((AnterosSecurityGrantedAuthority) authority)
								.equalsTo(systemName, resourceName, actionName)) {
							return ACCESS_GRANTED;
						}

					} else {
						if (((SecurityConfig) attribute).getAttribute().equalsIgnoreCase(authority.getAuthority())) {
							return ACCESS_GRANTED;
						}
					}
				}
			}
		}

		return result;
	}

	Collection<? extends GrantedAuthority> extractAuthorities(Authentication authentication) {
		return authentication.getAuthorities();
	}

}