package com.aurionpro.repository;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.aurionpro.entity.UserPlan;

public interface UserPlanRepository extends JpaRepository<UserPlan, Integer>{
	
	List<UserPlan> findByUserIdAndExpiryDateAfter(int userId, LocalDateTime now);
	List<UserPlan> findByPlanId(int planId);
	List<UserPlan> findByUserId(int userId);
}
