package com.aurionpro.dto.url;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@AllArgsConstructor
@RequiredArgsConstructor
@Data
public class UrlResponseDto {
	
	private String shorturl;
	private boolean iscustom;
	private int clicksRemaining;

}
