package com.aurionpro.dto.shorturl;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@AllArgsConstructor
@RequiredArgsConstructor
@Data
public class ShortUrlRequestDto {
	
	 @NotBlank(message = "Original URL must not be blank")
	    private String originalUrl;

	    @NotNull(message = "User ID must not be null")
	    @Min(value = 1, message = "User ID must be a valid positive number")
	    private int userId;

	    @NotNull(message = "Plan ID must not be null")
	    @Min(value = 1, message = "Plan ID must be a valid positive number")
	    private int planid;

}
