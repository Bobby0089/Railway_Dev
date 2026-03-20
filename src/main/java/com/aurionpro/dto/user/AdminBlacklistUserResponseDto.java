package com.aurionpro.dto.user;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@AllArgsConstructor
@RequiredArgsConstructor
@Data
public class AdminBlacklistUserResponseDto {
	
	private int id;
	private String username;
	private String firstname;
	private String lastname;
	private boolean isblacklist;

}
