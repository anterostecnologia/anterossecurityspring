package br.com.anteros.security.spring.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import br.com.anteros.security.spring.AnterosSecurityManager;

@Configuration
@EnableWebSecurity
@ComponentScan(basePackages = { "br.com.anteros.security" })
public abstract class AnterosSpringSecurityConfiguration extends WebSecurityConfigurerAdapter {

	public abstract String systemName();

	public abstract String description();

	public abstract String version();

	public abstract Boolean adminNeedsPermission();

	public abstract String packageToScanSecurity();

	@Autowired
	private AnterosSecurityManager anterosSecurityManager;

	@Override
	protected AuthenticationManager authenticationManager() throws Exception {
		configureAnterosSecurityManager();
		final List<AuthenticationProvider> providers = new ArrayList<AuthenticationProvider>(1);
		providers.add(anterosSecurityManager);
		return new ProviderManager(providers);
	}

	private void configureAnterosSecurityManager() throws Exception {
		anterosSecurityManager.setDescription(description()).setAdminNeedsPermission(adminNeedsPermission())
				.setSystemName(systemName()).setVersion(version()).setPackageToScanSecurity(packageToScanSecurity())
				.configure();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.cors().and().authorizeRequests().antMatchers("/resources/**").permitAll().antMatchers("/login*").permitAll()
				.anyRequest().authenticated().and().formLogin().and().httpBasic();
	}

	@Autowired
	public void configureGlobalSecurity(AuthenticationManagerBuilder auth) throws Exception {
		configureAnterosSecurityManager();
		auth.authenticationProvider(anterosSecurityManager);
	}
	
	
	@Bean
    public CorsConfigurationSource corsConfigurationSource() {
        final CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("HEAD",
                "GET", "POST", "PUT", "DELETE", "PATCH"));
        // setAllowCredentials(true) is important, otherwise:
        // The value of the 'Access-Control-Allow-Origin' header in the response must not be the wildcard '*' when the request's credentials mode is 'include'.
        configuration.setAllowCredentials(true);
        // setAllowedHeaders is important! Without it, OPTIONS preflight request
        // will fail with 403 Invalid CORS request
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
	

}
