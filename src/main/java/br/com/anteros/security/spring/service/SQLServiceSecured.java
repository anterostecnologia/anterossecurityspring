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
package br.com.anteros.security.spring.service;

import java.io.Serializable;
import java.util.List;

import br.com.anteros.persistence.dsl.osql.types.OrderSpecifier;
import br.com.anteros.persistence.dsl.osql.types.Predicate;
import br.com.anteros.persistence.metadata.identifier.Identifier;
import br.com.anteros.persistence.session.repository.Page;
import br.com.anteros.persistence.session.repository.Pageable;
import br.com.anteros.persistence.session.service.SQLService;
import br.com.anteros.security.spring.ActionSecured;

public interface SQLServiceSecured<T,ID extends Serializable> extends SQLService<T, ID> {

	@ActionSecured(actionName="ACT_saveOne", category="Edição", description="Salvar um entidade")
	<S extends T> S save(S entity);

	@ActionSecured(actionName="ACT_saveMany", category="Edição", description="Salvar várias entidades")
	<S extends T> Iterable<S> save(Iterable<S> entities);

	@ActionSecured(actionName="ACT_saveAndFlush", category="Edição", description="Salvar e descarregar uma entidade")
	<S extends T> S saveAndFlush(S entity);

	@ActionSecured(actionName="ACT_flush", category="Edição", description="Descarregar comandos da sessão")
	void flush();

	@ActionSecured(actionName="ACT_findOne", category="Busca", description="Busca uma entidade")
	T findOne(ID id);

	@ActionSecured(actionName="ACT_exists", category="Busca", description="Verifica se uma entidade existe")
	boolean exists(ID id);

	@ActionSecured(actionName="ACT_findAll", category="Busca", description="Busca todas as entidades")
	List<T> findAll();

	@ActionSecured(actionName="ACT_findAllWithPage", category="Busca", description="Busca todas as entidades com paginação")
	Page<T> findAll(Pageable pageable);

	@ActionSecured(actionName="ACT_find", category="Busca", description="Busca as entidades usando sql")
	List<T> find(String sql);

	@ActionSecured(actionName="ACT_findWithPage", category="Busca", description="Busca as entidades usando sql e paginação")
	Page<T> find(String sql, Pageable pageable);

	@ActionSecured(actionName="ACT_findWithParameters", category="Busca", description="Busca as entidades usando sql e parameters")
	List<T> find(String sql, Object parameters);

	@ActionSecured(actionName="ACT_findWithParametersAndPage", category="Busca", description="Busca as entidades usando sql com parâmetros e paginação")
	Page<T> find(String sql, Object parameters, Pageable pageable);

	@ActionSecured(actionName="ACT_findByNamedQuery", category="Busca", description="Busca as entidades usando consulta nomeada")
	List<T> findByNamedQuery(String queryName);

	@ActionSecured(actionName="ACT_findByNamedQueryWithPage", category="Busca", description="Busca as entidades usando consulta nomeada e paginação")
	Page<T> findByNamedQuery(String queryName, Pageable pageable);

	@ActionSecured(actionName="ACT_findByNamedQueryWithParameters", category="Busca", description="Busca as entidades usando consulta nomeada com parâmetros")
	List<T> findByNamedQuery(String queryName, Object parameters);

	@ActionSecured(actionName="ACT_findByNamedQueryWithParamsAndPage", category="Busca", description="Busca as entidades usando consulta nomeada com parâmetros")
	Page<T> findByNamedQuery(String queryName, Object parameters, Pageable pageable);

	@ActionSecured(actionName="ACT_findOneWithPredicate", category="Busca", description="Busca uma entidade usando predicado")
	T findOne(Predicate predicate);

	@ActionSecured(actionName="ACT_findOneBySql", category="Busca", description="Busca uma entidade")
	T findOneBySql(String sql);

	@ActionSecured(actionName="ACT_findOneBySqlWithParameters", category="Busca", description="Busca uma entidade usando sql e parâmetros")
	T findOneBySql(String sql, Object parameters);

	@ActionSecured(actionName="ACT_findAllWithPredicate", category="Busca", description="Busca todas as entidades com predicado")
	List<T> findAll(Predicate predicate);

	@ActionSecured(actionName="ACT_findAllWithPredicateAndOrder", category="Busca", description="Busca todas as entidades com predicado/ordenação")
	Iterable<T> findAll(Predicate predicate, OrderSpecifier<?>... orders);

	@ActionSecured(actionName="ACT_findAllWithPredicateAndPage", category="Busca", description="Busca todas as entidades com predicado/paginação")
	Page<T> findAll(Predicate predicate, Pageable pageable);

	@ActionSecured(actionName="ACT_remove", category="Edição", description="Remove uma entidade")
	Page<T> findAll(Predicate predicate, Pageable pageable, OrderSpecifier<?>... orders);

	@ActionSecured(actionName="ACT_refresh", category="Edição", description="Atualiza um objeto")
	void refresh(T entity);

	@ActionSecured(actionName="ACT_count", category="Edição", description="Conta a quantidade de objetos")
	long count();

	@ActionSecured(actionName="ACT_countByPredicate", category="Edição", description="Conta a quantidade de objetos usando predicado")
	long count(Predicate predicate);

	@ActionSecured(actionName="ACT_removeById", category="Edição", description="Remove uma entidade pelo ID")
	void remove(ID id);

	@ActionSecured(actionName="ACT_remove", category="Edição", description="Remove uma entidade")
	void remove(T entity);

	@ActionSecured(actionName="ACT_removeMany", category="Edição", description="Remove várias entidades")
	void remove(Iterable<? extends T> entities);

	@ActionSecured(actionName="ACT_removeAll", category="Edição", description="Remove todas as entidades")
	void removeAll();

	@ActionSecured(actionName="ACT_createIdentifier", category="Edição", description="Cria um identificador")
	Identifier<T> createIdentifier() throws Exception;

	@ActionSecured(actionName="ACT_getIdentifier", category="Edição", description="Obtém um identificador")
	Identifier<T> getIdentifier(T owner) throws Exception;
}
