package br.com.anteros.security.spring;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Repository;

import br.com.anteros.persistence.parameter.NamedParameter;
import br.com.anteros.persistence.session.SQLSessionFactory;
import br.com.anteros.persistence.session.repository.impl.GenericSQLRepository;
import br.com.anteros.security.model.Security;
import br.com.anteros.security.model.User;

@Repository("anterosSecurityRepository")
public class AnterosSecurityRepositoryImpl extends GenericSQLRepository<Security, Long> implements
		AnterosSecurityRepository {

	@Autowired
	public AnterosSecurityRepositoryImpl(@Qualifier("sessionFactory") SQLSessionFactory sessionFactory) {
		super(sessionFactory);
	}

	public User findUserByName(String userName) {
		return (User) findOne("select * from SEGURANCA where login = :plogin", new NamedParameter("plogin", userName));
	}

}
