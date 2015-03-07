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

	public static void manualAuthentication(UserDetails user, String systemName, String version, boolean adminNeedsPermission) {
		if (user == null) {
			throw new BadCredentialsException("Username is required.");
		}

		((AnterosSecurityUser) user).setSystemName(systemName);
		((AnterosSecurityUser) user).setVersion(version);
		((AnterosSecurityUser) user).setAdminNeedsPermission(adminNeedsPermission);

		Collection<? extends GrantedAuthority> authorities = user.getAuthorities();
		SecurityContextHolder.getContext().setAuthentication(
				new AnterosSecurityAuthenticationToken(user, user.getPassword(), authorities));
	}

}
