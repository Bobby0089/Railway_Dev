package com.aurionpro.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.aurionpro.dto.PageResponse.PageResponseDto;
import com.aurionpro.dto.transaction.TransactionResponseDto;
import com.aurionpro.service.transaction.TransactionService;

@RestController
@RequestMapping("urlapp/transaction")
//@CrossOrigin(origins = "http://localhost:4200/")
public class TransactionController {
	
	@Autowired
	private TransactionService transactionService;
	
	@GetMapping("/getallTransaction")
	public ResponseEntity<PageResponseDto<TransactionResponseDto>> getAllUsers(@RequestParam int pageNumber, @RequestParam int pageSize)
	{
		return ResponseEntity.ok(transactionService.getAllTransaction(pageNumber, pageSize));
	}
	
	 @GetMapping("/count")
		public ResponseEntity<Long> getTransactionCount(){
			return ResponseEntity.ok(transactionService.getTotalTransaction());
		}

}
