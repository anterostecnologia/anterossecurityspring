package br.com.anteros.security.spring;

import java.util.Collection;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class AnterosSecurityAuthenticationToken extends UsernamePasswordAuthenticationToken{

	private static final long serialVersionUID = 1L;

	public AnterosSecurityAuthenticationToken(Object principal, Object credentials) {
		super(principal, credentials);
	}
	
	public AnterosSecurityAuthenticationToken(Object principal, Object credentials,
			Collection<? extends GrantedAuthority> authorities) {
		super(principal, credentials, authorities);
	}

}
