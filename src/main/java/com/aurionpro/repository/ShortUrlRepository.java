package com.aurionpro.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.aurionpro.entity.ShortUrl;

public interface ShortUrlRepository extends JpaRepository<ShortUrl, Integer>{
	
	Optional<ShortUrl> findByShortCode(String shortCode);
	Optional<ShortUrl> findByOriginalUrlAndUserId(String originalUrl, int userId);
	 boolean existsByShortCode(String shortCode);

}
