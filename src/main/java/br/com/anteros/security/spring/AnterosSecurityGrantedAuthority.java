package br.com.anteros.security.spring;

import org.springframework.security.core.GrantedAuthority;

import br.com.anteros.core.utils.Assert;

public class AnterosSecurityGrantedAuthority implements GrantedAuthority {

	private static final long serialVersionUID = 1L;
	private final String systemName;
	private final String resourceName;
	private final String actionName;

	public AnterosSecurityGrantedAuthority(String systemName, String resourceName, String actionName) {
		Assert.hasText(systemName, "The name of system is required for AnterosSecurityGrantedAuthority");
		Assert.hasText(resourceName, "The name of resource is required for AnterosSecurityGrantedAuthority");
		Assert.hasText(actionName, "The name of action is required for AnterosSecurityGrantedAuthority");
		this.systemName = systemName;
		this.resourceName = resourceName;
		this.actionName = actionName;
	}

	public String getAuthority() {
		return this.actionName;
	}

	public String getSystemName() {
		return systemName;
	}

	public String getResourceName() {
		return resourceName;
	}

	public String getActionName() {
		return actionName;
	}

	public boolean equalsTo(String systemName, String resourceName, String actionName) {
		if (!systemName.equalsIgnoreCase(this.systemName))
			return false;

		if (!resourceName.equalsIgnoreCase(this.resourceName))
			return false;

		if (!actionName.equalsIgnoreCase(this.actionName))
			return false;

		return true;
	}

}
