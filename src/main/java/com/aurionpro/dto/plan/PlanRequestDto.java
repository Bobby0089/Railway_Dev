package com.aurionpro.dto.plan;

import com.aurionpro.enums.Type;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@AllArgsConstructor
@RequiredArgsConstructor
@Data
public class PlanRequestDto {

	@NotBlank(message = "Plan name must not be blank")
    private String planname;

    @NotNull(message = "Plan type must not be null")
    private Type type;

    @Min(value = 1, message = "URL limit must be at least 1")
    private int urllimit;

    @Min(value = 1, message = "Clicks per URL must be at least 1")
    private int clicksperurl;

    @Min(value = 0, message = "Custom URL limit must be zero or more")
    private int customerlimit;

    @Positive(message = "Price must be positive")
    private double price;
}
