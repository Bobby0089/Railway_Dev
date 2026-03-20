package com.aurionpro.service.plan;


import java.util.ArrayList;
import java.util.List;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import com.aurionpro.dto.PageResponse.PageResponseDto;
import com.aurionpro.dto.plan.PlanRequestDto;
import com.aurionpro.dto.plan.PlanResponseDto;
import com.aurionpro.entity.Plan;
import com.aurionpro.exception.ApiException;
import com.aurionpro.repository.PlanRepository;

@Service
public class PlanServiceImpl implements PlanService {

	@Autowired
	private PlanRepository planRepository;
	@Autowired
	private ModelMapper mapper;

	@Override
	public PlanResponseDto createPlan(PlanRequestDto planDto) {
		Plan plan = mapper.map(planDto, Plan.class);
		planRepository.save(plan);
		return mapper.map(plan, PlanResponseDto.class);
	}

	@Override
	public PlanResponseDto updatePlan(PlanResponseDto planDto) {
		Plan plan = planRepository.findById(planDto.getId()).orElseThrow(() -> new ApiException("Plan not found"));
		plan.setPlanname(planDto.getPlanname());
		plan.setClicksperurl(planDto.getClicksperurl());
		plan.setCustomerlimit(planDto.getCustomerlimit());
		plan.setUrllimit(planDto.getUrllimit());
		plan.setPrice(planDto.getPrice());
		plan.setType(planDto.getType());
		planRepository.save(plan);
		return mapper.map(plan, PlanResponseDto.class);
	}

	@Override
	public PageResponseDto<PlanResponseDto> viewPlan(int pagenumber, int pagesize) {
		Pageable pageable = PageRequest.of(pagenumber, pagesize);

		Page<Plan> pageuser = planRepository.findAll(pageable);
		PageResponseDto<PlanResponseDto> pageResponseDto = new PageResponseDto<>();

		pageResponseDto.setPagenumber(pageuser.getNumber());
		pageResponseDto.setPagesize(pageuser.getSize());
		pageResponseDto.setTotalpages(pageuser.getTotalPages());
		pageResponseDto.setTotalelements(pageuser.getTotalElements());
		List<Plan> dbusers = pageuser.getContent();
		List<PlanResponseDto> dtoUsers = new ArrayList<>();
		for (Plan plan : dbusers) {
			if (plan.isIsactive()) {
				PlanResponseDto dto = mapper.map(plan, PlanResponseDto.class);
				dtoUsers.add(dto);
			}
		}
		pageResponseDto.setContent(dtoUsers);
		pageResponseDto.setIslast(pageuser.isLast());
		return pageResponseDto;
	}

}
