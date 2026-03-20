package com.aurionpro.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.aurionpro.entity.ShortUrl;
import com.aurionpro.entity.Url;

public interface UrlRepository extends JpaRepository<Url, Integer>{
	
	Optional<Url> findByShorturl(String shorturl);
	
}
