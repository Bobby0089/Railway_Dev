package com.aurionpro.dto.userPlan;

import java.util.List;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@AllArgsConstructor
@RequiredArgsConstructor
@Data
public class BuyPlanRequest {
	
	@NotNull(message = "User ID must not be null")
    @Min(value = 1, message = "User ID must be a valid positive number")
    private int userId;

    @NotEmpty(message = "At least one plan ID must be provided")
    private List<@NotNull(message = "Plan ID cannot be null") @Min(value = 1, message = "Plan ID must be positive") Integer> planIds;

}
