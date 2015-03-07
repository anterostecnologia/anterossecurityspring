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

import org.springframework.security.core.GrantedAuthority;

import br.com.anteros.security.model.Action;

/**
 * 
 * @author Edson Martins edsonmartins2005@gmail.com
 *
 */
public class AnterosSecurityGrantedAuthority implements GrantedAuthority {

	private static final long serialVersionUID = 1L;
	
	private String authoriy;
	private String systemName;
	private String resourceName;
	private String actionName;
	
	
	public AnterosSecurityGrantedAuthority(Action action) {
		makeAuthority(action);
	}

	private void makeAuthority(Action action) {
		this.authoriy = action.getNome();
		this.systemName = action.getRecurso().getSistema().getNome();
		this.resourceName = action.getRecurso().getNome();
		this.actionName = action.getNome();
	}

	public String getAuthority() {
		return authoriy;
	}

	public String getSystemName() {
		return systemName;
	}

	public String getResourceName() {
		return resourceName;
	}

	public String getActionName() {
		return actionName;
	}

	public boolean equalsTo(String systemName, String resourceName, String actionName) {
		if (!systemName.equalsIgnoreCase(this.getSystemName()))
			return false;

		if (!resourceName.equalsIgnoreCase(this.getResourceName()))
			return false;

		if (!actionName.equalsIgnoreCase(this.getActionName()))
			return false;

		return true;
	}

}
