package com.aurionpro.dto.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@AllArgsConstructor
@RequiredArgsConstructor
@Data
public class UserRegisterDto {
	
	@NotBlank(message = "Username must not be blank")
    private String username;

    @NotBlank(message = "First name must not be blank")
    private String firstname;

    @NotBlank(message = "Last name must not be blank")
    private String lastname;

    @NotBlank(message = "Email must not be blank")
    @Email(message = "Email must be valid")
    private String email;

    @NotBlank(message = "Password must not be blank")
    @Size(min = 4, message = "Password must be at least 4 characters long")
    private String password;

    @NotBlank(message = "Role must not be blank")
	private String role;

}
