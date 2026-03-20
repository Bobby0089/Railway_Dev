package com.aurionpro.service.url;

import java.util.List;

import org.springframework.http.HttpStatus;

import com.aurionpro.dto.url.UrlRequestDto;
import com.aurionpro.dto.url.UrlResponseDto;

public interface UrlService {
	
	HttpStatus addUrl(UrlRequestDto dto);
	List<UrlResponseDto> getallurls();

}
