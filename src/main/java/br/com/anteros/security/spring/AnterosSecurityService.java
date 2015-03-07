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
package br.com.anteros.security.spring;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import br.com.anteros.persistence.session.service.SQLService;
import br.com.anteros.security.model.Action;
import br.com.anteros.security.model.Resource;
import br.com.anteros.security.model.Security;
import br.com.anteros.security.model.System;
import br.com.anteros.security.model.User;

/**
 * 
 * @author Edson Martins
 *
 */
public interface AnterosSecurityService extends UserDetailsService, SQLService<Security, Long> {

	public Resource getResourceByName(String systemName, String resourceName);
	
	public System getSystemByName(String systemName);
	
	public System addSystem(String systemName, String description) throws Exception;

	public Resource addResource(System system, String resourceName, String description) throws Exception;

	public Action addAction(System system, Resource resource, String actionName, String category, String description, String version) throws Exception;

	public Action saveAction(Action action) throws Exception;

	public Resource refreshResource(Resource resource) throws Exception;

	public void removeActionByAllUsers(Action act) throws Exception;
	
	public UserDetails loadUserByUsername(String username, String systemName) throws UsernameNotFoundException;
	
	public User getUserByUserName(String username);
	
	
}
