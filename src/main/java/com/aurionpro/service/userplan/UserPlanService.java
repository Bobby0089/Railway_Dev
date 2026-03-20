package com.aurionpro.service.userplan;

import java.util.List;

import org.springframework.http.HttpStatus;

import com.aurionpro.dto.userPlan.BuyPlanRequest;
import com.aurionpro.dto.userPlan.UserPlanResponseDto;

public interface UserPlanService {
	
	public HttpStatus buyPlans(BuyPlanRequest request);

	List<UserPlanResponseDto> viewUserPlans(int userid);

}
