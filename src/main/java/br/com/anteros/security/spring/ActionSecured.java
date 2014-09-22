package br.com.anteros.security.spring;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.security.access.annotation.Secured;

@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@Secured("ACT_ANTEROS")
public @interface ActionSecured {

	String actionName();
	
	String category();
	
	String description();
	
	boolean requiresAdmin() default false;
}
