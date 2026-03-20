package com.aurionpro.security;

import java.util.Set;
import java.util.stream.Collectors;
import com.aurionpro.entity.User; // ✅ this should be your entity

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.aurionpro.repository.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService{
	
	@Autowired
	private UserRepository userRepo;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepo.findByUsername(username)
				.orElseThrow(() -> new UsernameNotFoundException("User id not found"));
		
		Set<GrantedAuthority> authorities = user
				.getRoles()
				.stream()
				.map((role) -> new SimpleGrantedAuthority(role.getRolename())).collect(Collectors.toSet());
		
		return new org.springframework.security.core.userdetails.User(user.getUsername(),
				user.getPassword(),
				authorities);
		
	}

}
