package com.aurionpro.service.userplan;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import com.aurionpro.dto.userPlan.BuyPlanRequest;
import com.aurionpro.dto.userPlan.UserPlanResponseDto;
import com.aurionpro.entity.Plan;
import com.aurionpro.entity.Transaction;
import com.aurionpro.entity.User;
import com.aurionpro.entity.UserPlan;
import com.aurionpro.exception.ApiException;
import com.aurionpro.repository.PlanRepository;
import com.aurionpro.repository.TransactionRepository;
import com.aurionpro.repository.UserPlanRepository;
import com.aurionpro.repository.UserRepository;

@Service
public class UserPlanServiceImpl implements UserPlanService {

	@Autowired
	private UserPlanRepository userPlanRepository;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private PlanRepository planRepository;
	
	@Autowired
	private TransactionRepository transactionRepository;

	@Override
	public HttpStatus buyPlans(BuyPlanRequest request) {
		User user = userRepository.findById(request.getUserId())
				.orElseThrow(() -> new ApiException("User not found"));
		
		Transaction transaction = new Transaction();
		

		List<UserPlan> activeUserPlans = userPlanRepository.findByUserIdAndExpiryDateAfter(user.getId(),
				LocalDateTime.now());

		List<Integer> alreadyOwnedPlanIds = activeUserPlans.stream().map(up -> up.getPlan().getId())
				.collect(Collectors.toList());

		List<Integer> requestedPlanIds = request.getPlanIds();

		List<Integer> plansToBuy = requestedPlanIds.stream().filter(planId -> !alreadyOwnedPlanIds.contains(planId))
				.collect(Collectors.toList());

		if (plansToBuy.isEmpty()) {
			return null;
		}

		List<Plan> plans = planRepository.findAllById(plansToBuy);

		for (Plan plan : plans) {
			UserPlan userPlan = new UserPlan();
			userPlan.setUser(user);
			transaction.setUser(user);
			userPlan.setPlan(plan);
			transaction.setPlanName(plan.getPlanname());
			transaction.setPrice(plan.getPrice());
			transaction.setTransactionDate(LocalDateTime.now());
			userPlan.setRemainingUrls(plan.getUrllimit());
			userPlan.setRemainingClicks(plan.getClicksperurl());
			userPlan.setExpiryDate(LocalDateTime.now().plusMonths(1));
			userPlan.setCustomUrlLimit(plan.getCustomerlimit());
			transactionRepository.save(transaction);
			userPlanRepository.save(userPlan);
		}

		return HttpStatus.ACCEPTED;
	}

	@Override
	public List<UserPlanResponseDto> viewUserPlans(int userid) {
		    List<UserPlan> userPlans = userPlanRepository.findByUserId(userid);

		    List<UserPlanResponseDto> planDtos = new ArrayList<>();
		    
		    for (UserPlan userplan : userPlans) {
		    	UserPlanResponseDto planDto = new UserPlanResponseDto();
		        planDto.setId(userplan.getPlan().getId());
		        planDto.setPlanname(userplan.getPlan().getPlanname());
		        planDto.setType(userplan.getPlan().getType());
		        planDto.setClicksperurl(userplan.getPlan().getClicksperurl());
		        planDto.setUrllimit(userplan.getRemainingUrls());
		        planDto.setPrice(userplan.getPlan().getPrice());
		        planDto.setCustomurllimit(userplan.getPlan().getCustomerlimit());
		        planDtos.add(planDto);
		    }
		    
		    return planDtos;
	}

}
