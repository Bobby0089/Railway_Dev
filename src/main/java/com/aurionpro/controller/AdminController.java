package com.aurionpro.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.aurionpro.dto.admin.AdminRequestDto;
import com.aurionpro.dto.admin.AdminResponseDto;
import com.aurionpro.service.admin.AdminService;
import com.aurionpro.service.users.UserService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("urlapp/admin")
//@CrossOrigin(origins = "http://localhost:4200/")
public class AdminController {
	
	@Autowired
	private AdminService adminService;

	
	@PostMapping("/register")
	public ResponseEntity<AdminResponseDto> registerAdmin(@Valid @RequestBody AdminRequestDto adminDto)
	{
		return ResponseEntity.ok(adminService.register(adminDto));
	}
	
	@PostMapping("/login")
	public  ResponseEntity<AdminResponseDto> loginAdmin(@Valid @RequestBody AdminRequestDto adminDto)
	{
		return ResponseEntity.ok(adminService.login(adminDto));
	}


}
