package com.aurionpro.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.aurionpro.dto.PageResponse.PageResponseDto;
import com.aurionpro.dto.shorturl.AdminShortUrlResponseDto;
import com.aurionpro.dto.shorturl.CustomUrlResponseDto;
import com.aurionpro.dto.shorturl.RenewRequestDto;
import com.aurionpro.dto.shorturl.ShortUrlRequestDto;
import com.aurionpro.dto.shorturl.ShortUrlResponseDto;
import com.aurionpro.repository.ShortUrlRepository;
import com.aurionpro.service.shoturl.ShortUrlService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("urlapp/generateurl")
//@CrossOrigin(origins = "http://localhost:4200/")
public class ShortUrlController {
	
	 @Autowired	
	 private ShortUrlService service;
	 @Autowired	
	 private ShortUrlRepository shortUrlRepo;
	 
	 @PostMapping("/short")
	    public ResponseEntity<ShortUrlResponseDto> generateShortUrl(@Valid @RequestBody ShortUrlRequestDto dto) {
	        return ResponseEntity.ok(service.generateShortUrl(dto));
	    }
	 
	 @PostMapping("/customshort")
	    public ResponseEntity<ShortUrlResponseDto> generatecustomShortUrl(@Valid @RequestBody CustomUrlResponseDto dto) {
	        return ResponseEntity.ok(service.generatecustomShortUrl(dto));
	    }
	 
	 @PostMapping("/renew")
	    public ResponseEntity<HttpStatus> renewUrl(@Valid @RequestBody RenewRequestDto dto) {
	        return ResponseEntity.ok(service.renewUrl(dto));
	    }
	 
	 @GetMapping("/view")
		public ResponseEntity<PageResponseDto<AdminShortUrlResponseDto>> viewallUrls(@RequestParam int pageNumber, @RequestParam int pageSize)
		{
			return ResponseEntity.ok(service.getAllUrls(pageNumber, pageSize));
		}
	 
	 @GetMapping("/viewUserUrls")
		public ResponseEntity<PageResponseDto<AdminShortUrlResponseDto>> viewUrlOfAUser(@RequestParam int pageNumber, @RequestParam int pageSize, @RequestParam int userId )
		{
			return ResponseEntity.ok(service.getUserUrl(pageNumber, pageSize, userId));
		}
	 
	 @GetMapping("/count")
		public ResponseEntity<Long> getUrlCount(){
			return ResponseEntity.ok(service.getTotalUrl());
		}
}
