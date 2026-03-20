package com.aurionpro.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.aurionpro.entity.Transaction;

public interface TransactionRepository extends JpaRepository<Transaction, Integer>{

}
