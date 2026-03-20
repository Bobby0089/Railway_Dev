package com.aurionpro.dto.userQuery;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@AllArgsConstructor
@RequiredArgsConstructor
@Data
public class AdminQueryRequestDto {
	
	 @NotBlank(message = "Status must not be blank")
	    private String status;

	    @NotBlank(message = "Response text must not be blank")
	    private String responseText;

	    private boolean resolved; 
	    
	    private int id;

}
