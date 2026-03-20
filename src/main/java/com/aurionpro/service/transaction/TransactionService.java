package com.aurionpro.service.transaction;

import com.aurionpro.dto.PageResponse.PageResponseDto;
import com.aurionpro.dto.transaction.TransactionResponseDto;


public interface TransactionService {
	
	PageResponseDto<TransactionResponseDto> getAllTransaction(int pagenumber,int pagesize);

	long getTotalTransaction();

}
