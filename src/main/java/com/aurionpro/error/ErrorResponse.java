package com.aurionpro.error;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@AllArgsConstructor
@Data
public class ErrorResponse {
	
	private String message;
	private int status;
	private long timestamp;

}
