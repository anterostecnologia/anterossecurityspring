package br.com.anteros.security.spring.repository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Repository;

import br.com.anteros.persistence.session.SQLSessionFactory;
import br.com.anteros.persistence.session.repository.impl.GenericSQLRepository;
import br.com.anteros.security.model.Resource;

@Repository("anterosResourceRepository")
@Scope("prototype")
public class AnterosResourceRepositoryImpl extends GenericSQLRepository<Resource, Long> implements AnterosResourceRepository {

	@Autowired
	public AnterosResourceRepositoryImpl(@Qualifier("sessionFactory") SQLSessionFactory sessionFactory) throws Exception {
		super(sessionFactory);
	}

}
