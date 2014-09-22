package br.com.anteros.security.spring;

import org.springframework.security.core.GrantedAuthority;

import br.com.anteros.security.model.Action;

public class AnterosSecurityGrantedAuthority implements GrantedAuthority {

	private static final long serialVersionUID = 1L;
	private Action action;
	
	public AnterosSecurityGrantedAuthority(Action action) {
		this.action = action;
	}

	public String getAuthority() {
		return this.action.getNome();
	}

	public String getSystemName() {
		return this.action.getRecurso().getSistema().getNome();
	}

	public String getResourceName() {
		return this.action.getRecurso().getNome();
	}

	public String getActionName() {
		return this.action.getNome();
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

	public Action getAction() {
		return action;
	}

	public void setAction(Action action) {
		this.action = action;
	}

}
