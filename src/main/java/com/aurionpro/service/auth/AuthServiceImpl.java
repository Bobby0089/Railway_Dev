package com.aurionpro.service.auth;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.aurionpro.dto.auth.UserLoginDto;
import com.aurionpro.dto.auth.UserRegisterDto;
import com.aurionpro.entity.Role;
import com.aurionpro.entity.User;
import com.aurionpro.exception.ApiException;
import com.aurionpro.exception.UserApiException;
import com.aurionpro.repository.RoleRepository;
import com.aurionpro.repository.UserRepository;
import com.aurionpro.security.JwtTokenProvider;

import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;

@Service
@AllArgsConstructor
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService{
	@Autowired
	private AuthenticationManager authenticationManager;
	@Autowired
	private UserRepository userRepository;
	@Autowired
	private PasswordEncoder passwordEncoder;
	@Autowired
	private JwtTokenProvider jwtTokenProvider;
	@Autowired
	private RoleRepository roleRepository;

	@Override
	public User register(UserRegisterDto registration) {
		if(userRepository.existsByUsername(registration.getUsername()))
			throw new UserApiException(HttpStatus.BAD_REQUEST, "User already exists");

		User user = new User();
		user.setUsername(registration.getUsername());
		user.setPassword(passwordEncoder.encode(registration.getPassword()));
		
		List<Role> roles = new ArrayList<Role>();
		
		Role role = roleRepository.findByRolename(registration.getRole())
			    .orElseThrow(() -> new ApiException("Role 'USER' not found in database"));
		roles.add(role);
		user.setRoles(roles);
		
		user.setFirstname(registration.getFirstname());
		user.setLastname(registration.getLastname());
		user.setEmail(registration.getEmail());
		
		
		return userRepository.save(user);
	}

	@Override
	public String login(UserLoginDto loginDto) {
	
			try
			{
				//here we are authenticating our user and this is (first part) to authenticate the user  => (first part)
				Authentication authentication = authenticationManager.authenticate(
						new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword()));
				
				//It is used to store the authenticated user information in the Security Context for the current request.
				SecurityContextHolder.getContext().setAuthentication(authentication);
					
				// here we are generating jwt token and this comes in (second part)	=> (second part)
				String token = jwtTokenProvider.generateToken(authentication);
						return token;
				
			}catch(BadCredentialsException e)
			{
				throw new UserApiException(HttpStatus.NOT_FOUND,"User not found");
			}		
				
	}
}


