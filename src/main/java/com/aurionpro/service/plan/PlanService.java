package com.aurionpro.service.plan;

import com.aurionpro.dto.PageResponse.PageResponseDto;
import com.aurionpro.dto.plan.PlanRequestDto;
import com.aurionpro.dto.plan.PlanResponseDto;

public interface PlanService {

	PlanResponseDto createPlan(PlanRequestDto planDto);
	
	PlanResponseDto updatePlan(PlanResponseDto planDto);

	PageResponseDto<PlanResponseDto> viewPlan(int pagenumber, int pagesize);
}
