package com.aurionpro.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.aurionpro.dto.PageResponse.PageResponseDto;
import com.aurionpro.dto.plan.PlanRequestDto;
import com.aurionpro.dto.plan.PlanResponseDto;
import com.aurionpro.service.plan.PlanService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("urlapp/plan")
//@CrossOrigin(origins = "http://localhost:4200/")
public class PlanController {
	
	@Autowired
	private PlanService planService;
	
	@PostMapping("/create")
	public ResponseEntity<PlanResponseDto> createPlan(@Valid @RequestBody PlanRequestDto planDto){
		return ResponseEntity.ok(planService.createPlan(planDto));
	}

	@PutMapping("/update")
	public ResponseEntity<PlanResponseDto> updatePlan(@Valid @RequestBody PlanResponseDto planDto){
		return ResponseEntity.ok(planService.updatePlan(planDto));
	}
	
	@GetMapping("/view")
	public ResponseEntity<PageResponseDto<PlanResponseDto>> viewPlan(@RequestParam int pageNumber, @RequestParam int pageSize){
		return ResponseEntity.ok(planService.viewPlan(pageNumber,pageSize));
	}
}
