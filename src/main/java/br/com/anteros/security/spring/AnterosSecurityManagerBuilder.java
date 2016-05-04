package br.com.anteros.security.spring;

import br.com.anteros.core.utils.Assert;
import br.com.anteros.persistence.session.SQLSessionFactory;

public class AnterosSecurityManagerBuilder {

	private boolean adminNeedsPermission=false;
	private String packageToScanSecurity="";
	private String systemName;
	private String version;
	private String description;
	private SQLSessionFactory sessionFactory;

	public AnterosSecurityManagerBuilder() {
		super();
	}
	
	public AnterosSecurityManagerBuilder adminNeedsPermission(boolean adminNeedsPermission){
		this.adminNeedsPermission = adminNeedsPermission;
		return this;
	}
	
	public AnterosSecurityManagerBuilder packageToScanSecurity(String packageToScanSecurity){
		this.packageToScanSecurity = packageToScanSecurity;
		return this;
	}
	
	public AnterosSecurityManagerBuilder systemName(String systemName){
		this.systemName = systemName;
		return this;
	}
	
	public AnterosSecurityManagerBuilder version(String version){
		this.version = version;
		return this;
	}
	
	public AnterosSecurityManagerBuilder description(String description){
		this.description = description;
		return this;
	}
	
	public AnterosSecurityManagerBuilder sessionFactory(SQLSessionFactory sessionFactory){
		this.sessionFactory = sessionFactory;
		return this;
	}
	
	
	public AnterosSecurityManager build() throws Exception{
		Assert.notNull(systemName,
				"Para o correto funcionamento da segurança da aplicação é necessário informar o nome do sistema.");
		Assert.notNull(version,
				"Para o correto funcionamento da segurança da aplicação é necessário informar a versão do sistema.");
		Assert.notNull(description,
				"Para o correto funcionamento da segurança da aplicação é necessário informar a descrição do sistema.");
		Assert.notNull(sessionFactory,
				"Para o correto funcionamento da segurança da aplicação é necessário informar a fábrica de sessões de persistência(SQLSessionFactory).");
		AnterosSecurityManager securityManager = new AnterosSecurityManager();
		securityManager.setAdminNeedsPermission(Boolean.valueOf(adminNeedsPermission));
		securityManager.setPackageToScanSecurity(packageToScanSecurity);
		securityManager.setSystemName(systemName);
		securityManager.setVersion(version);
		securityManager.setDescription(description);
		securityManager.afterPropertiesSet();
		return securityManager;
	}
	
	
       
       
}
