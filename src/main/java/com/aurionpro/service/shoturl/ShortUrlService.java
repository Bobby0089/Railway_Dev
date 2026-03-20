package com.aurionpro.service.shoturl;

import org.springframework.http.HttpStatus;

import com.aurionpro.dto.PageResponse.PageResponseDto;
import com.aurionpro.dto.shorturl.AdminShortUrlResponseDto;
import com.aurionpro.dto.shorturl.CustomUrlResponseDto;
import com.aurionpro.dto.shorturl.RenewRequestDto;
import com.aurionpro.dto.shorturl.ShortUrlRequestDto;
import com.aurionpro.dto.shorturl.ShortUrlResponseDto;

public interface ShortUrlService {
	
	public ShortUrlResponseDto generateShortUrl(ShortUrlRequestDto request);
	public ShortUrlResponseDto generatecustomShortUrl(CustomUrlResponseDto request);
	public HttpStatus renewUrl(RenewRequestDto dto);
	public PageResponseDto<AdminShortUrlResponseDto> getAllUrls(int pagenumber,int pagesize);
	public PageResponseDto<AdminShortUrlResponseDto> getUserUrl(int pageNumber, int pageSize, int userId);
	long getTotalUrl();

}
