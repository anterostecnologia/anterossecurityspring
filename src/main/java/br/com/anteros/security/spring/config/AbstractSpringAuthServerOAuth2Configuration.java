package br.com.anteros.security.spring.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

import br.com.anteros.security.spring.AnterosSecurityManager;

@Configuration
@EnableAuthorizationServer
public abstract class AbstractSpringAuthServerOAuth2Configuration extends AuthorizationServerConfigurerAdapter {
	
	@Autowired
	private TokenStore tokenStore;

	@Autowired
	private AnterosSecurityManager authenticationManager;

	public abstract PasswordEncoder getOAuth2ClientPasswordEncoder();

	@Bean
	public OAuth2AccessDeniedHandler oauthAccessDeniedHandler() {
		return new OAuth2AccessDeniedHandler();
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer) {
		oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()")
				.passwordEncoder(getOAuth2ClientPasswordEncoder());
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		System.out.println(getOAuth2ClientPasswordEncoder().encode("senha_secreta"));
		clients.withClientDetails(authenticationManager);
//		clients.inMemory().withClient("spring-security-oauth2-read-write-client")
//				.authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
//				.authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT").scopes("read", "write", "trust")
//				.secret("$2a$04$soeOR.QFmClXeFIrhJVLWOQxfHjsJLSpWrU1iGxcMGdu.a5hvfY4W")
//				.accessTokenValiditySeconds(10800).// Access token is only valid for 2 minutes.
//				refreshTokenValiditySeconds(2592000);// Refresh token is only valid for 10 minutes.
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
		endpoints.tokenStore(tokenStore).authenticationManager(authenticationManager)
				.userDetailsService(authenticationManager)
				.allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST);		
	}

}
