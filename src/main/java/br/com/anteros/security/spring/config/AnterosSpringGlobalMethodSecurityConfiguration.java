package br.com.anteros.security.spring.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

import br.com.anteros.security.spring.AnterosSecurityAccessDecisionManager;
import br.com.anteros.security.spring.AnterosSecurityVoter;


public class AnterosSpringGlobalMethodSecurityConfiguration extends GlobalMethodSecurityConfiguration {

	@Bean
	public AnterosSecurityAccessDecisionManager anterosSecurityMethodAccessDecisionManager() {
		List<AccessDecisionVoter<? extends Object>> decisionVoters = new ArrayList<AccessDecisionVoter<? extends Object>>();
		decisionVoters.add(new AnterosSecurityVoter());
		AnterosSecurityAccessDecisionManager result = new AnterosSecurityAccessDecisionManager(decisionVoters);
		return result;
	}
	

	@Override
	protected AccessDecisionManager accessDecisionManager() {
		return anterosSecurityMethodAccessDecisionManager();
	}

}
