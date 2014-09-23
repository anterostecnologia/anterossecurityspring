package br.com.anteros.security.spring;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import br.com.anteros.security.model.Action;
import br.com.anteros.security.model.User;

public class AnterosSecurityUser implements UserDetails {

	private static final long serialVersionUID = 1L;
	private User internalUser;
	private String systemName;
	private String version;
	private boolean adminNeedsPermission = true;
	private Set<AnterosSecurityGrantedAuthority> actions;

	public AnterosSecurityUser(User user) {
		this.internalUser = user;
	}

	public Collection<? extends GrantedAuthority> getAuthorities() {
		if (actions == null) {
			actions = new HashSet<AnterosSecurityGrantedAuthority>();
			for (Action action : internalUser.getAcoes()) {
				if (action.getRecurso().getSistema().getNome().equalsIgnoreCase(systemName))
					actions.add(new AnterosSecurityGrantedAuthority(action));
			}
			if (internalUser.getPerfil() != null) {
				for (Action action : internalUser.getPerfil().getAcoes()) {
					if (action.getRecurso().getSistema().getNome().equalsIgnoreCase(systemName))
						actions.add(new AnterosSecurityGrantedAuthority(action));
				}
			}
		}

		return actions;
	}

	public String getPassword() {
		return internalUser.getSenha();
	}

	public String getUsername() {
		return internalUser.getLogin();
	}

	public boolean isAccountNonExpired() {
		return (!internalUser.isExpirada());
	}

	public boolean isAccountNonLocked() {
		return !internalUser.getContaBloqueada();
	}

	public boolean isCredentialsNonExpired() {
		return (!internalUser.isExpirada());
	}

	public boolean isEnabled() {
		return (!internalUser.getContaBloqueada() && (!internalUser.getContaDesativada()));
	}

	public boolean isAdmin() {
		return internalUser.getBoAdministrador();
	}

	public String getSystemName() {
		return systemName;
	}

	public void setSystemName(String systemName) {
		this.systemName = systemName;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public boolean isAdminNeedsPermission() {
		return adminNeedsPermission;
	}

	public void setAdminNeedsPermission(boolean adminNeedsPermission) {
		this.adminNeedsPermission = adminNeedsPermission;
	}

}
