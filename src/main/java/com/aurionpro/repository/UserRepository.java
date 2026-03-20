package com.aurionpro.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.aurionpro.entity.User;

public interface UserRepository extends JpaRepository<User, Integer>{
	
	boolean existsByUsername(String username);
	
	boolean existsByPassword(String password);
	
	Optional<User> findByUsername(String username);
	
	Optional<User> findByPassword(String password);
	
	long count();


}
