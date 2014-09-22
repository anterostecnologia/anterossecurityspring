package br.com.anteros.security.spring;

public class AnterosSecurityException extends RuntimeException {

	public AnterosSecurityException() {
	}

	public AnterosSecurityException(String msg) {
		super(msg);
	}

	public AnterosSecurityException(Throwable e) {
		super(e);
	}

	public AnterosSecurityException(String msg, Throwable e) {
		super(msg, e);
	}

}
