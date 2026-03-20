package com.aurionpro.dto.user;

import com.aurionpro.entity.Role;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@AllArgsConstructor
@RequiredArgsConstructor
@Data
public class UserResponseDto {

	private int id;
	private String username;
	private String firstname;
	private String lastname;
	private String email;
	private String password;
	private Role role;
}
