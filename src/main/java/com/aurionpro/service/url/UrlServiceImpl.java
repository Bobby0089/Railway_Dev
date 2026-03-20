package com.aurionpro.service.url;

import java.util.ArrayList;
import java.util.List;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import com.aurionpro.dto.url.UrlRequestDto;
import com.aurionpro.dto.url.UrlResponseDto;
import com.aurionpro.entity.Url;
import com.aurionpro.repository.UrlRepository;

@Service
public class UrlServiceImpl implements UrlService{
	
	@Autowired
	private UrlRepository repository;
	@Autowired
	private ModelMapper mapper;

	@Override
	public HttpStatus addUrl(UrlRequestDto dto) {
		repository.save(mapper.map(dto, Url.class));
		return HttpStatus.ACCEPTED;
	}

	@Override
	public List<UrlResponseDto> getallurls() {
		List<Url> urls = repository.findAll();
		List<UrlResponseDto> dtos = new ArrayList<>();
		for(Url u:urls ) {
			dtos.add(mapper.map(u, UrlResponseDto.class));
		}
		return dtos;
	}

}
