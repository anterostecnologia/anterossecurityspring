package br.com.anteros.security.spring;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import br.com.anteros.security.model.User;

public class AnterosSecurityUser implements UserDetails {

	private static final long serialVersionUID = 1L;
	private User internalUser;

	public AnterosSecurityUser(User user) {
		this.internalUser = user;
	}

	public Collection<? extends GrantedAuthority> getAuthorities() {
		List<GrantedAuthority> result = new ArrayList<GrantedAuthority>();
		if (internalUser.getLogin().equals("edson")) {
			result.add(new AnterosSecurityGrantedAuthority("Roratus", "Servico", "ACT_podeExecutarMetodo1"));
			result.add(new AnterosSecurityGrantedAuthority("Roratus", "Servico", "ACT_podeExecutarMetodo2"));
		} else
			result.add(new AnterosSecurityGrantedAuthority("Roratus", "Servico", "ACT_podeExecutarMetodo2"));
		return result;
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

}
