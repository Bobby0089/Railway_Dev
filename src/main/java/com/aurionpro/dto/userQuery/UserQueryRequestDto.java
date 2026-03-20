package com.aurionpro.dto.userQuery;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@AllArgsConstructor
@RequiredArgsConstructor
@Data
public class UserQueryRequestDto {

	 @NotBlank(message = "Query text must not be blank")
	    private String queryText;

	    @NotNull(message = "User ID must not be null")
	    @Min(value = 1, message = "User ID must be a valid positive number")
	    private int userid;
	
}
