package br.com.anteros.security.spring;

import br.com.anteros.persistence.session.repository.SQLRepository;
import br.com.anteros.security.model.Security;
import br.com.anteros.security.model.User;

public interface AnterosSecurityRepository extends SQLRepository<Security, Long>{

	User findUserByName(String userName);
}
