package br.com.anteros.security.spring;

import org.springframework.security.core.AuthenticationException;

public class UserBlockedAccountException extends AuthenticationException {

	public UserBlockedAccountException(String msg, Throwable t) {
		super(msg, t);
	}

	public UserBlockedAccountException(String msg) {
		super(msg);
	}
}
