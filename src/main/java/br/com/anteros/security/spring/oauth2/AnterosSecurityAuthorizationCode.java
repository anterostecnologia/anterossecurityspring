package br.com.anteros.security.spring.oauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.stereotype.Component;

import br.com.anteros.security.store.SecurityDataStore;

@Component("authorizationCode")
public class AnterosSecurityAuthorizationCode implements AuthorizationCodeServices {
	
	@Autowired
	private SecurityDataStore securityDataStore;

	public String createAuthorizationCode(OAuth2Authentication authentication) {
		// TODO Auto-generated method stub
		return null;
	}

	public OAuth2Authentication consumeAuthorizationCode(String code) throws InvalidGrantException {
		// TODO Auto-generated method stub
		return null;
	}

}
