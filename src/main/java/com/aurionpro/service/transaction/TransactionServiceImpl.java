package com.aurionpro.service.transaction;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import com.aurionpro.dto.PageResponse.PageResponseDto;
import com.aurionpro.dto.transaction.TransactionResponseDto;
import com.aurionpro.dto.user.AdminUserResponseDto;
import com.aurionpro.entity.ShortUrl;
import com.aurionpro.entity.Transaction;
import com.aurionpro.entity.User;
import com.aurionpro.entity.UserPlan;
import com.aurionpro.repository.TransactionRepository;

@Service
public class TransactionServiceImpl implements TransactionService{
	
	@Autowired
	private TransactionRepository transactionRepository;

	@Override
	public PageResponseDto<TransactionResponseDto> getAllTransaction(int pagenumber, int pagesize) {
		Pageable pageable = PageRequest.of(pagenumber, pagesize);

		Page<Transaction> pagetransaction = transactionRepository.findAll(pageable);
		PageResponseDto<TransactionResponseDto> pageResponseDto = new PageResponseDto<>();

		pageResponseDto.setPagenumber(pagetransaction.getNumber());
		pageResponseDto.setPagesize(pagetransaction.getSize());
		pageResponseDto.setTotalpages(pagetransaction.getTotalPages());
		pageResponseDto.setTotalelements(pagetransaction.getTotalElements());
		List<Transaction> dbtransaction = pagetransaction.getContent();
		List<TransactionResponseDto> dtoTransaction = new ArrayList<>();
		for (Transaction transaction : dbtransaction) {
			TransactionResponseDto transactionResponseDto= new TransactionResponseDto();
			transactionResponseDto.setId(transaction.getId());
			transactionResponseDto.setPlanName(transaction.getPlanName());
			transactionResponseDto.setPrice(transaction.getPrice());
			transactionResponseDto.setTransactionDate(transaction.getTransactionDate());
			User user = transaction.getUser();
			transactionResponseDto.setUsername(user.getUsername());
			
			dtoTransaction.add(transactionResponseDto);
		}
		pageResponseDto.setContent(dtoTransaction);
		pageResponseDto.setIslast(pagetransaction.isLast());
		return pageResponseDto;
	}

	@Override
	public long getTotalTransaction() {
		
		return transactionRepository.count();
	}

}
