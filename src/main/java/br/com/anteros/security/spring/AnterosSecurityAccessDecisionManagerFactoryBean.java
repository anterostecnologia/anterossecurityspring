package br.com.anteros.security.spring;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.access.AccessDecisionVoter;

public class AnterosSecurityAccessDecisionManagerFactoryBean  implements FactoryBean<AnterosSecurityAccessDecisionManager>, InitializingBean {
	private AnterosSecurityAccessDecisionManager accessDecisionManager;

	public AnterosSecurityAccessDecisionManagerFactoryBean() {
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		buildAccessDecisionManager();		
	}

	private void buildAccessDecisionManager() {
		List<AccessDecisionVoter<? extends Object>> decisionVoters = new ArrayList<AccessDecisionVoter<? extends Object>>();
		decisionVoters.add(new AnterosSecurityVoter());
		accessDecisionManager = new AnterosSecurityAccessDecisionManager(decisionVoters);
		
	}

	@Override
	public AnterosSecurityAccessDecisionManager getObject() throws Exception {
		return accessDecisionManager;
	}

	@Override
	public Class<?> getObjectType() {
		return AnterosSecurityAccessDecisionManager.class;
	}

	@Override
	public boolean isSingleton() {
		return false;
	}

}
