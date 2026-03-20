package com.aurionpro.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.aurionpro.entity.Admin;


public interface AdminRepository extends JpaRepository<Admin, Integer> {

	boolean existsByUsername(String username);

	boolean existsByPassword(String password);

	Optional<Admin> findByUsername(String username);

	Optional<Admin> findByPassword(String password);

}
