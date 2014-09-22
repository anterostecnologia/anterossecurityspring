package br.com.anteros.security.spring.util;

import java.util.Collection;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import br.com.anteros.security.spring.AnterosSecurityAuthenticationToken;
import br.com.anteros.security.spring.AnterosSecurityUser;

public final class AnterosSecurityUtil {

	public static AnterosSecurityUser getLoggedUser() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null)
			return null;
		return (AnterosSecurityUser) authentication.getPrincipal();
	}

	public static void clearAuthentication() {
		SecurityContextHolder.getContext().setAuthentication(null);
	}

	public static void manualAuthentication(UserDetails user, String systemName, String version) {
		if (user == null) {
			throw new BadCredentialsException("Username is required.");
		}

		((AnterosSecurityUser) user).setSystemName(systemName);
		((AnterosSecurityUser) user).setVersion(version);

		Collection<? extends GrantedAuthority> authorities = user.getAuthorities();
		SecurityContextHolder.getContext().setAuthentication(
				new AnterosSecurityAuthenticationToken(user, user.getPassword(), authorities));
	}

}
