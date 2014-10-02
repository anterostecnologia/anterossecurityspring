package br.com.anteros.security.spring;

import org.springframework.security.core.GrantedAuthority;

import br.com.anteros.security.model.Action;

public class AnterosSecurityGrantedAuthority implements GrantedAuthority {

	private static final long serialVersionUID = 1L;
	
	private String authoriy;
	private String systemName;
	private String resourceName;
	private String actionName;
	
	
	public AnterosSecurityGrantedAuthority(Action action) {
		makeAuthority(action);
	}

	private void makeAuthority(Action action) {
		this.authoriy = action.getNome();
		this.systemName = action.getRecurso().getSistema().getNome();
		this.resourceName = action.getRecurso().getNome();
		this.actionName = action.getNome();
	}

	public String getAuthority() {
		return authoriy;
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
		if (!systemName.equalsIgnoreCase(this.getSystemName()))
			return false;

		if (!resourceName.equalsIgnoreCase(this.getResourceName()))
			return false;

		if (!actionName.equalsIgnoreCase(this.getActionName()))
			return false;

		return true;
	}

}
