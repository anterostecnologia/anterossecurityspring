package br.com.anteros.security.spring.repository;

import br.com.anteros.persistence.session.repository.SQLRepository;
import br.com.anteros.security.model.Action;

public interface AnterosActionRepository extends SQLRepository<Action, Long>{

}
