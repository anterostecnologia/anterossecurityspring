package br.com.anteros.security.spring;

import org.springframework.security.core.userdetails.UserDetailsService;

import br.com.anteros.persistence.session.service.SQLService;
import br.com.anteros.security.model.Action;
import br.com.anteros.security.model.Resource;
import br.com.anteros.security.model.Security;
import br.com.anteros.security.model.System;

public interface AnterosSecurityService extends UserDetailsService, SQLService<Security, Long> {

	public Resource getResourceByName(String systemName, String resourceName);
	
	public System getSystemByName(String systemName);
	
	public System addSystem(String systemName, String description) throws Exception;

	public Resource addResource(System system, String resourceName, String description) throws Exception;

	public Action addAction(System system, Resource resource, String actionName, String category, String description, String version) throws Exception;

	public Action saveAction(Action action) throws Exception;

	public Resource refreshResource(Resource resource) throws Exception;

	public void removeActionByAllUsers(Action act) throws Exception;
	
	
}
