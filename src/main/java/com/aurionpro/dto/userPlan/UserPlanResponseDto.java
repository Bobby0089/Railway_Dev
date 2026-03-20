package com.aurionpro.dto.userPlan;

import com.aurionpro.enums.Type;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@AllArgsConstructor
@RequiredArgsConstructor
@Data
public class UserPlanResponseDto {
	
	private int id;
	private String planname;
	private Type type;
	private int urllimit;
	private int clicksperurl;
	private int customurllimit;
	private double price;

}
