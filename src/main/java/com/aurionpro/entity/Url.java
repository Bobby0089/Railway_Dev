package com.aurionpro.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Entity
@Table(name="Urls")
@AllArgsConstructor
@RequiredArgsConstructor
@Data
public class Url {
	
	 @Id
	    @GeneratedValue(strategy = GenerationType.IDENTITY)
	    private int id;

	    @NotBlank(message = "Short URL must not be blank")
	    private String shorturl;

	    private boolean iscustom;

	    @Min(value = 0, message = "Clicks Remaining must be zero or positive")
	    private int clicksRemaining;

	    @Min(value = 1, message = "Plan ID must be valid and greater than 0")
	    private int planId;
}
