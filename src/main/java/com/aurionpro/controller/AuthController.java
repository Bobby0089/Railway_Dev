package com.aurionpro.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.aurionpro.dto.auth.JwtAuthResponse;
import com.aurionpro.dto.auth.UserLoginDto;
import com.aurionpro.dto.auth.UserRegisterDto;
import com.aurionpro.entity.User;
import com.aurionpro.service.auth.AuthService;

@RestController
@RequestMapping("/urlapp/auth")
//@CrossOrigin(origins="http://localhost:4200")
public class AuthController {
	
	@Autowired
	private AuthService authService;
	
	@PostMapping("/register")
	public ResponseEntity<User> registerUser(@RequestBody UserRegisterDto dto)
	{
		return ResponseEntity.ok(authService.register(dto));
	}

	@PostMapping("/login")
	public ResponseEntity<JwtAuthResponse> login(@RequestBody UserLoginDto loginDto)
	{
		String token = authService.login(loginDto);
	
		JwtAuthResponse jwtAuthResponse = new JwtAuthResponse();
		jwtAuthResponse.setAccessToken(token);
		
		return ResponseEntity.ok(jwtAuthResponse);
	}
	

}
