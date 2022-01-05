package br.com.anteros.security.spring;

import org.springframework.security.core.AuthenticationException;

public class UserInactiveAccountException extends AuthenticationException {
	public UserInactiveAccountException(String msg, Throwable t) {
		super(msg, t);
	}

	public UserInactiveAccountException(String msg) {
		super(msg);
	}
}
