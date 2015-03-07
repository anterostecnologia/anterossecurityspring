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

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import br.com.anteros.security.model.Action;
import br.com.anteros.security.model.User;

/**
 * Representação de um usuário dentro do sistema de segurança do Anteros.
 * 
 * @author Edson Martins
 *
 */
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
