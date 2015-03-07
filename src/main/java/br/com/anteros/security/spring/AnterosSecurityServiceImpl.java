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

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import br.com.anteros.persistence.parameter.NamedParameter;
import br.com.anteros.persistence.session.SQLSession;
import br.com.anteros.persistence.session.service.GenericSQLService;
import br.com.anteros.security.model.Action;
import br.com.anteros.security.model.Resource;
import br.com.anteros.security.model.Security;
import br.com.anteros.security.model.System;
import br.com.anteros.security.model.User;
import br.com.anteros.security.spring.repository.AnterosActionRepository;
import br.com.anteros.security.spring.repository.AnterosResourceRepository;
import br.com.anteros.security.spring.repository.AnterosSecurityRepository;
import br.com.anteros.security.spring.repository.AnterosSystemRepository;

/**
 * 
 * @author Edson Martins
 *
 */
@Service("anterosSecurityService")
public class AnterosSecurityServiceImpl extends GenericSQLService<Security, Long> implements AnterosSecurityService,
		InitializingBean {

	@Autowired
	protected AnterosSecurityRepository anterosSecurityRepository;

	@Autowired
	protected AnterosSystemRepository anterosSystemRepository;

	@Autowired
	protected AnterosResourceRepository anterosResourceRepository;

	@Autowired
	protected AnterosActionRepository anterosActionRepository;

	private Map<String, AnterosSecurityUser> cacheUsers = new HashMap<String, AnterosSecurityUser>();

	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		AnterosSecurityUser result = cacheUsers.get(username);
		if (result == null) {
			User user = anterosSecurityRepository.findUserByName(username);
			if (user == null)
				return null;
			result = new AnterosSecurityUser(user);
			user = null;
			cacheUsers.put(username, result);
		}
		return result;
	}
	
	public UserDetails loadUserByUsername(String username, String systemName) throws UsernameNotFoundException {
		AnterosSecurityUser result = cacheUsers.get(username);
		if (result == null) {
			User user = anterosSecurityRepository.findUserByName(username);
			if (user == null)
				return null;
			result = new AnterosSecurityUser(user, systemName);
			user = null;
			cacheUsers.put(username, result);
		}
		return result;
	}

	public Resource getResourceByName(String systemName, String resourceName) {
		//TODO  Trocar por consulta via DSL para evitar problemas com nomes.
		Resource resource = anterosResourceRepository
				.findOne(
						"select rec.* from SEGURANCARECURSO rec, SEGURANCASISTEMA sis where sis.nome_sistema = :pnome_sistema and rec.nome_recurso = :pnome_recurso and rec.id_sistema = sis.id_sistema ",
						NamedParameter.list().addParameter("pnome_sistema", systemName)
								.addParameter("pnome_recurso", resourceName).values());
		return resource;
	}

	public System getSystemByName(String systemName) {
		//TODO  Trocar por consulta via DSL para evitar problemas com nomes.
		System system = anterosSystemRepository.findOne(
				"select sis.* from SEGURANCASISTEMA sis where sis.nome_sistema = :pnome_sistema", new NamedParameter(
						"pnome_sistema", systemName));
		return system;
	}

	public System addSystem(String systemName, String description) throws Exception {
		System system = new System();
		system.setNome(systemName);
		system.setDescricao(description);
		try {
			anterosSystemRepository.getSession().getTransaction().begin();
			anterosSystemRepository.getSession().save(system);
			anterosSystemRepository.getSession().getTransaction().commit();
		} catch (Exception e) {
			anterosSystemRepository.getSession().getTransaction().rollback();
			throw new AnterosSecurityException("Não foi possível salvar o sistema " + systemName + ". "
					+ e.getMessage(), e);
		}

		return system;
	}

	public Resource addResource(System system, String resourceName, String description) throws Exception {
		Resource resource = new Resource();
		resource.setNome(resourceName);
		resource.setDescricao(description);
		resource.setSistema(system);
		try {
			anterosResourceRepository.getSession().getTransaction().begin();
			anterosResourceRepository.getSession().save(resource);
			anterosResourceRepository.getSession().getTransaction().commit();
		} catch (Exception e) {
			anterosResourceRepository.getSession().getTransaction().rollback();
			throw new AnterosSecurityException("Não foi possível salvar o recurso " + resourceName + ". "
					+ e.getMessage(), e);
		}

		return resource;
	}

	public Action addAction(System system, Resource resource, String actionName, String category, String description,
			String version) throws Exception {
		Action action = new Action();
		action.setNome(actionName);
		action.setDescricao(description);
		action.setCategoria(category);
		action.setRecurso(resource);
		action.setVersao(version);
		try {
			anterosActionRepository.getSession().getTransaction().begin();
			anterosActionRepository.getSession().save(action);
			anterosActionRepository.getSession().getTransaction().commit();
		} catch (Exception e) {
			anterosActionRepository.getSession().getTransaction().rollback();
			throw new AnterosSecurityException("Não foi possível salvar a ação " + actionName + ". " + e.getMessage(),
					e);
		}
		return action;
	}

	public Action saveAction(Action action) throws Exception {
		try {
			anterosActionRepository.getSession().getTransaction().begin();
			anterosActionRepository.getSession().save(action);
			anterosActionRepository.getSession().getTransaction().commit();
		} catch (Exception e) {
			anterosActionRepository.getSession().getTransaction().rollback();
			throw new AnterosSecurityException(e);
		}
		return action;
	}

	public Resource refreshResource(Resource resource) {
		anterosResourceRepository.refresh(resource);
		return resource;
	}

	public void removeActionByAllUsers(Action act) throws Exception {
		try {
			anterosActionRepository.getSession().getTransaction().begin();
			//TODO  Trocar por consulta via DSL para evitar problemas com nomes.
			anterosActionRepository
					.getSession()
					.createQuery("delete from SEGURANCAACAOACAO where id_acao = :pid_acao",
							new NamedParameter("pid_acao", act.getId())).executeQuery();
			anterosActionRepository.remove(act);
			anterosActionRepository.getSession().getTransaction().commit();
		} catch (Exception e) {
			anterosActionRepository.getSession().getTransaction().rollback();
			throw new AnterosSecurityException(e);
		}
	}

	public void afterPropertiesSet() throws Exception {
		SQLSession session = anterosSecurityRepository.getSQLSessionFactory().openSession();
		anterosSecurityRepository.setSession(session);
		anterosActionRepository.setSession(session);
		anterosResourceRepository.setSession(session);
		anterosSystemRepository.setSession(session);
	}

	
	public User getUserByUserName(String username){
		return anterosSecurityRepository.findUserByName(username);
	}
}
