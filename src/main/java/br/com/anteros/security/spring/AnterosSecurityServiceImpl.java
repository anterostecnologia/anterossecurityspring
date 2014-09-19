package br.com.anteros.security.spring;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import br.com.anteros.security.model.User;

@Service("anterosSecurityService")
public class AnterosSecurityServiceImpl implements AnterosSecurityService {

	@Autowired
	protected AnterosSecurityRepository anterosSecurityRepository;

	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = anterosSecurityRepository.findUserByName(username);
		if (user == null)
			return null;
		return new AnterosSecurityUser(user);
	}

}
