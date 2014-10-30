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
	private String userName;
	private String password;
	private String systemName;
	private String version;
	private boolean adminNeedsPermission = true;
	private Set<AnterosSecurityGrantedAuthority> actions;
	private boolean accountExpired;
	private boolean accountLocked;
	private boolean accountInactive;
	private boolean admin;

	public AnterosSecurityUser(User user) {
		makeUser(user);
		user=null;
	}
	
	public AnterosSecurityUser(User user, String systemName) {
		this.systemName = systemName;
		makeUser(user);
		user=null;
	}

	private void makeUser(User user) {
		this.userName = user.getLogin();
		this.password = user.getSenha();
		this.accountExpired = user.isExpirada();
		this.accountInactive = user.getContaDesativada();
		this.accountLocked = user.getContaBloqueada();
		this.admin = user.getBoAdministrador();
		actions = new HashSet<AnterosSecurityGrantedAuthority>();
		for (Action action : user.getAcoes()) {
			if ((systemName==null) || (action.getRecurso().getSistema().getNome().equalsIgnoreCase(systemName)))
				actions.add(new AnterosSecurityGrantedAuthority(action));
		}
		if (user.getPerfil() != null) {
			for (Action action : user.getPerfil().getAcoes()) {
				if ((systemName==null) || (action.getRecurso().getSistema().getNome().equalsIgnoreCase(systemName)))
					actions.add(new AnterosSecurityGrantedAuthority(action));
			}
		}
	}

	public Collection<? extends GrantedAuthority> getAuthorities() {
		return actions;
	}

	public String getPassword() {
		return password;
	}

	public String getUsername() {
		return userName;
	}

	public boolean isAccountNonExpired() {
		return !accountExpired;
	}

	public boolean isAccountNonLocked() {
		return !accountLocked;
	}

	public boolean isCredentialsNonExpired() {
		return !accountExpired;
	}

	public boolean isEnabled() {
		return (!accountLocked && (!accountInactive));
	}

	public boolean isAdmin() {
		return admin;
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
