package br.com.anteros.security.spring.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import br.com.anteros.security.spring.AnterosSecurityManager;

@Configuration
@EnableResourceServer
public abstract class AbstractSpringResourceServerConfiguration extends ResourceServerConfigurerAdapter {
	
	@Autowired
    private AnterosSecurityManager authenticationManager;

	@Override
	public void configure(ResourceServerSecurityConfigurer resources) {
		ResourceServerTokenServices tokenServices = getResourceServerTokenServicesToAuthentication();
		if (tokenServices != null) {
			resources.tokenServices(tokenServices);
			authenticationManager.setTokenServices(tokenServices);
			authenticationManager.setResourceId(getResourceId());
		}
		
		
		
		resources.resourceId(getResourceId());
		resources.authenticationManager(authenticationManager);
		
	}

	public abstract String getResourceId();

	public abstract String getSecuredPattern();

	public abstract ResourceServerTokenServices getResourceServerTokenServicesToAuthentication();

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.requestMatchers().antMatchers(getSecuredPattern())
		.and().cors()
		.and().authorizeRequests()
		.anyRequest().authenticated()
		.and().csrf().disable();
		//.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

	}

}
