package com.aurionpro.dto.userQuery;

import java.time.LocalDateTime;

import org.springframework.http.HttpStatus;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@AllArgsConstructor
@RequiredArgsConstructor
@Data
public class UserQueryResponseDto {
	
	private int id;
	private String queryText;
	private String status;
	private String responseText;

}
