package com.aurionpro.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.aurionpro.dto.userPlan.BuyPlanRequest;
import com.aurionpro.dto.userPlan.UserPlanResponseDto;
import com.aurionpro.service.userplan.UserPlanService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("urlapp/buyplan")
//@CrossOrigin(origins = "http://localhost:4200/")
public class UserPlanController {
	
	@Autowired
    private UserPlanService userPlanService;
	
	@PostMapping("/buy")
    public ResponseEntity<HttpStatus> buyPlans(@Valid @RequestBody BuyPlanRequest request) {
        return ResponseEntity.ok(userPlanService.buyPlans(request));
    }
	
	@GetMapping("/viewplan/{userid}")
	 public ResponseEntity<List<UserPlanResponseDto>> viewPlans(@PathVariable int userid) {
       return ResponseEntity.ok(userPlanService.viewUserPlans(userid));
   }

}
