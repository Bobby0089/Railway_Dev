package com.aurionpro.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.aurionpro.entity.Plan;

public interface PlanRepository extends JpaRepository<Plan, Integer>{

}
