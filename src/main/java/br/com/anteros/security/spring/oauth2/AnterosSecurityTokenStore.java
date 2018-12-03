package br.com.anteros.security.spring.oauth2;

import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Component;
import br.com.anteros.security.store.SecurityDataStore;

@Component("tokenStore")
public class AnterosSecurityTokenStore implements TokenStore {
	
	@Autowired
	private SecurityDataStore securityDataStore;
	
	private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();

	public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
		return readAuthentication(token.getValue());		
	}

	public OAuth2Authentication readAuthentication(String token) {
		return securityDataStore.readAuthentication(token);
	}

	public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
		securityDataStore.storeAccessToken(token, authentication, authenticationKeyGenerator);		
	}

	public OAuth2AccessToken readAccessToken(String tokenValue) {
		return securityDataStore.readAccessToken(tokenValue);
	}

	public void removeAccessToken(OAuth2AccessToken token) {
		securityDataStore.removeAccessToken(token);
		
	}

	public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
		securityDataStore.storeRefreshToken(refreshToken, authentication);		
	}

	public OAuth2RefreshToken readRefreshToken(String tokenValue) {
		return securityDataStore.readRefreshToken(tokenValue);
	}

	public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
		return securityDataStore.readAuthenticationForRefreshToken(token);
	}

	public void removeRefreshToken(OAuth2RefreshToken token) {
		securityDataStore.removeRefreshToken(token);		
	}

	public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
		securityDataStore.removeAccessTokenUsingRefreshToken(refreshToken);
		
	}

	public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {		
        return securityDataStore.getAccessToken(authentication, authenticationKeyGenerator);
	}

	public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
		return securityDataStore.findTokensByClientIdAndUserName(clientId, userName);
	}

	public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
		return securityDataStore.findTokensByClientId(clientId);
	}
	
	public AuthenticationKeyGenerator getAuthenticationKeyGenerator() {
		return authenticationKeyGenerator;
	}

	public void setAuthenticationKeyGenerator(AuthenticationKeyGenerator authenticationKeyGenerator) {
		this.authenticationKeyGenerator = authenticationKeyGenerator;
	}
	
}
