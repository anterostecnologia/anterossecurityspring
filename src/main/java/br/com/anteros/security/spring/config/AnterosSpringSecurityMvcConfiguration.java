package br.com.anteros.security.spring.config;

import java.util.List;

import javax.servlet.FilterRegistration;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRegistration.Dynamic;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.context.ContextLoaderListener;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import br.com.anteros.persistence.session.SQLSessionFactory;
import br.com.anteros.spring.transaction.AnterosTransactionManager;
import br.com.anteros.springWeb.converter.AnterosHttpMessageConverter;
import br.com.anteros.springWeb.support.OpenSQLSessionInViewFilter;

@Configuration
@EnableTransactionManagement
@EnableWebMvc
public abstract class AnterosSpringSecurityMvcConfiguration extends WebMvcConfigurerAdapter
		 {

	private static final String OPEN_SQL_SESSION_IN_VIEW_FILTER = "OpenSQLSessionInViewFilter";
	private static final String SPRING_SECURITY_FILTER_CHAIN = "springSecurityFilterChain";
	private static final String DISPATCHER = "dispatcher";
	
	@Autowired
	private SQLSessionFactory sessionFactory;

	public void onStartup(ServletContext servletContext) throws ServletException {
		AnnotationConfigWebApplicationContext appContext = new AnnotationConfigWebApplicationContext();

		if (getDisplayName() != null) {
			appContext.setDisplayName(getDisplayName());
		}
		if (registerFirstConfigurationClasses() != null) {
			for (Class<?> clz : registerFirstConfigurationClasses()) {
				appContext.register(clz);
			}
		}
		if (persistenceConfigurationClass()!=null){
			appContext.register(persistenceConfigurationClass());
		}
		
		if (mvcConfigurationClass()!=null){
			appContext.register(mvcConfigurationClass());
		}
		
		if (globalMethodSecurityConfigurationClass()!=null){
			appContext.register(globalMethodSecurityConfigurationClass());
		}
		
		if (securityConfigurationClass()!=null){
			appContext.register(securityConfigurationClass());
		}
		
		if (swaggerConfigurationClass()!=null){
			appContext.register(swaggerConfigurationClass());
		}
		
		if (jsonDocConfigurationClass()!=null){
			appContext.register(jsonDocConfigurationClass());
		}
		
		if (registerLastConfigurationClasses() != null) {
			for (Class<?> clz : registerLastConfigurationClasses()) {
				appContext.register(clz);
			}
		}
		appContext.setServletContext(servletContext);
		servletContext.addListener(new ContextLoaderListener(appContext));

		Dynamic servlet = servletContext.addServlet(DISPATCHER, new DispatcherServlet(appContext));
		servlet.addMapping("/");
		servlet.setLoadOnStartup(1);

		FilterRegistration.Dynamic springSecurityFilterChain = servletContext.addFilter(SPRING_SECURITY_FILTER_CHAIN,
				DelegatingFilterProxy.class);
		springSecurityFilterChain.addMappingForUrlPatterns(null, false, "/*");
		
		FilterRegistration.Dynamic openSQLSessionInViewFilterChain = servletContext.addFilter(OPEN_SQL_SESSION_IN_VIEW_FILTER,
				OpenSQLSessionInViewFilter.class);
		openSQLSessionInViewFilterChain.addMappingForUrlPatterns(null, false, "/*");
		
	}

	public abstract Class<?>[] registerFirstConfigurationClasses();
	public abstract Class<?>[] registerLastConfigurationClasses();
	
	public abstract Class<?> persistenceConfigurationClass();
	
	public abstract Class<?> mvcConfigurationClass();
	
	public abstract Class<?> swaggerConfigurationClass();
	
	public abstract Class<?> securityConfigurationClass();
	
	public abstract Class<?> jsonDocConfigurationClass();
	
	public abstract Class<?> globalMethodSecurityConfigurationClass();

	public abstract void addListener(ServletContext servletContext);

	public abstract String getDisplayName();

	@Autowired
	@Bean(name = "transactionManager")
	public PlatformTransactionManager txManager(DataSource dataSource, SQLSessionFactory sessionFactory) {
		if (dataSource != null && sessionFactory != null) {
			AnterosTransactionManager txManager = new AnterosTransactionManager();
			txManager.setDataSource(dataSource);
			txManager.setSessionFactory(sessionFactory);
			return txManager;
		}
		return null;
	}

	@Bean
	public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
		return new PropertySourcesPlaceholderConfigurer();
	}

	@Override
	public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
		super.configureMessageConverters(converters);
		converters.add(new AnterosHttpMessageConverter(sessionFactory));
	}

	@Override
	public void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
		configurer.enable();
	}

	@Override
	public void addResourceHandlers(ResourceHandlerRegistry registry) {
		super.addResourceHandlers(registry);
		registry.addResourceHandler("swagger-ui.html").addResourceLocations("classpath:/META-INF/resources/");
		registry.addResourceHandler("jsondoc-ui.html").addResourceLocations("classpath:/META-INF/resources/");
		registry.addResourceHandler("/webjars/**").addResourceLocations("classpath:/META-INF/resources/webjars/");
	}


}
