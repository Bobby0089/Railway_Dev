package com.aurionpro.dto.transaction;

import java.time.LocalDateTime;

import com.aurionpro.entity.User;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@AllArgsConstructor
@RequiredArgsConstructor
@Data
public class TransactionResponseDto {
	
	private int id;
	private String username;
	private String planName;
    private double price;
    private LocalDateTime transactionDate;
   

}
