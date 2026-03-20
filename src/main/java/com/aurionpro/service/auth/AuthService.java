package com.aurionpro.service.auth;

import com.aurionpro.dto.auth.UserLoginDto;
import com.aurionpro.dto.auth.UserRegisterDto;
import com.aurionpro.entity.User;

public interface AuthService {
	
	User register(UserRegisterDto registration);
	String login(UserLoginDto loginDto);

}
