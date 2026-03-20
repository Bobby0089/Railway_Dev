package com.aurionpro.dto.url;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@AllArgsConstructor
@RequiredArgsConstructor
@Data
public class UrlRequestDto {
	 @NotBlank(message = "Short URL must not be blank")
	    private String shorturl;

	    private boolean iscustom; // no validation needed for boolean

	    @Min(value = 0, message = "Clicks remaining must be zero or positive")
	    private int clicksRemaining;

	    @NotNull(message = "Plan ID must not be null")
	    @Min(value = 1, message = "Plan ID must be a valid positive number")
	    private int planId;
}
