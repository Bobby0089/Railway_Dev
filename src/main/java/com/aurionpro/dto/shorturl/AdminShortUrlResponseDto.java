package com.aurionpro.dto.shorturl;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@AllArgsConstructor
@RequiredArgsConstructor
@Data
public class AdminShortUrlResponseDto {
	
	private int id;
	private String originalUrl;
    private String shortCode;
    private String name;
    private boolean customUrl;
    private int totalclicks;

}
