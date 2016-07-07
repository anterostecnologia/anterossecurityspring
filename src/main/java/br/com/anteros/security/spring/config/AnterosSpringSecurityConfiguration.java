package br.com.anteros.security.spring.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

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
		http.authorizeRequests().antMatchers("/resources/**").permitAll().antMatchers("/login*").permitAll()
				.anyRequest().authenticated().and().formLogin().and().httpBasic();
	}

	@Autowired
	public void configureGlobalSecurity(AuthenticationManagerBuilder auth) throws Exception {
		configureAnterosSecurityManager();
		auth.authenticationProvider(anterosSecurityManager);
	}

}
