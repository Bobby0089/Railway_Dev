package com.aurionpro.controller;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.aurionpro.dto.url.ClickResponseDto;
import com.aurionpro.dto.url.UrlResponseDto;
import com.aurionpro.entity.ShortUrl;
import com.aurionpro.entity.Url;
import com.aurionpro.exception.ApiException;
import com.aurionpro.repository.ShortUrlRepository;
import com.aurionpro.repository.UrlRepository;
import com.aurionpro.service.url.UrlService;

@RestController
@RequestMapping("urlapp/urlclick")
//@CrossOrigin(origins = "http://localhost:4200/")
public class ClickController {
	
	 @Autowired	
	 private ShortUrlRepository shortUrlRepo;
	 @Autowired
	 private UrlRepository urlRepository;
	 @Autowired
	 private UrlService urlService;
	
	@GetMapping("/{shortCode}")
	 public ResponseEntity<ClickResponseDto> redirectToOriginalUrl(@PathVariable String shortCode) {
	     
	     Url url = urlRepository.findByShorturl(shortCode)
	    		 .orElseThrow(() -> new ApiException("Short URL not found"));
	     
	     if (url.getClicksRemaining()<=0)
	     {
	    	 throw new ApiException("Clicks limit exceeded for this plan ");
	     }

	     url.setClicksRemaining(url.getClicksRemaining()-1);
	     urlRepository.save(url);
	     
	     ShortUrl shortUrl = shortUrlRepo.findByShortCode(shortCode)
	    		 .orElseThrow(() -> new ApiException("Short URL not found"));
	     
	     ClickResponseDto dto = new ClickResponseDto();
	     dto.setUrl(shortUrl.getOriginalUrl());

	     return ResponseEntity.ok(dto); 
	 }
	
	@GetMapping("/getall")
	public ResponseEntity<List<UrlResponseDto>> getAllUrls(){
		return ResponseEntity.ok(urlService.getallurls());
	}

}
