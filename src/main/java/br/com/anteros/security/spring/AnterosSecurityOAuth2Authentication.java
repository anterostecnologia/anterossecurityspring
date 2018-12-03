package br.com.anteros.security.spring;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

public class AnterosSecurityOAuth2Authentication extends OAuth2Authentication {

	private Object principal;
	private Collection<GrantedAuthority> authorities;

	public AnterosSecurityOAuth2Authentication(Object principal, OAuth2Authentication auth,
			Collection<GrantedAuthority> authorities) {
		super(auth.getOAuth2Request(),auth);
		this.principal = principal;
		this.authorities = authorities;
	}
	
	@Override
	public Object getPrincipal() {
		return this.getUserAuthentication() == null ? this.getOAuth2Request().getClientId() : principal;
	}
	
	@Override
	public Collection<GrantedAuthority> getAuthorities() {
		return authorities;
	}

}
