package com.aurionpro.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.aurionpro.entity.UserQuery;

public interface UserQueryRepository extends JpaRepository<UserQuery, Integer>{

}
