package com.aurionpro.controller;

//import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.aurionpro.dto.PageResponse.PageResponseDto;
import com.aurionpro.dto.userQuery.AdminQueryRequestDto;
import com.aurionpro.dto.userQuery.AdminViewDto;
import com.aurionpro.dto.userQuery.UserQueryRequestDto;
import com.aurionpro.dto.userQuery.UserQueryResponseDto;
import com.aurionpro.service.userquery.UserQueryService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("urlapp/query")
//@CrossOrigin(origins = "http://localhost:4200/")
public class UserQueryController {
	
	@Autowired
	private UserQueryService queryService;
	
	@PostMapping("/assign")
	public ResponseEntity<HttpStatus> userAssignQuery(@Valid @RequestBody UserQueryRequestDto dto)
	{
		return ResponseEntity.ok(queryService.assignQuery(dto));
	}
	
	@GetMapping("/view")
	public ResponseEntity<PageResponseDto<AdminViewDto>> adminViewallQueries(@RequestParam int pageNumber, @RequestParam int pageSize)
	{
		return ResponseEntity.ok(queryService.viewAllUserQueries(pageNumber, pageSize));
	}
	
	@GetMapping("/getallquery")
	public ResponseEntity<PageResponseDto<UserQueryResponseDto>> userGetallQueries(@RequestParam int pageNumber, @RequestParam int pageSize, @RequestParam int userId)
	{
		return ResponseEntity.ok(queryService.getAllUserQueries(pageNumber,pageSize,userId));
	}
	
	@PutMapping("/adminResponse")
	public ResponseEntity<HttpStatus> adminResponseToUserQuery(@Valid @RequestBody AdminQueryRequestDto dto, @RequestParam int userQueryId)
	{
	    queryService.amdinRepsoneToUserQuery(dto, userQueryId);
	    return new ResponseEntity<>(HttpStatus.OK);
	}
	

	
}
