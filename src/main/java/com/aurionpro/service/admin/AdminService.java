package com.aurionpro.service.admin;

import org.springframework.http.HttpStatus;

import com.aurionpro.dto.admin.AdminRequestDto;
import com.aurionpro.dto.admin.AdminResponseDto;



public interface AdminService {
	
	AdminResponseDto register(AdminRequestDto adminDto);
	
	AdminResponseDto login(AdminRequestDto adminDto);

}
