package com.aurionpro.entity;

import java.time.LocalDateTime;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Entity
@Table(name="userplans")
@AllArgsConstructor
@RequiredArgsConstructor
@Data
public class UserPlan {
	
	 @Id
	    @GeneratedValue(strategy = GenerationType.IDENTITY)
	    private int id;

	    @Min(value = 0, message = "Remaining URLs must be zero or positive")
	    private int remainingUrls;

	    @Min(value = 0, message = "Remaining clicks must be zero or positive")
	    private int remainingClicks;

	    @NotNull(message = "Expiry date must not be null")
	    private LocalDateTime expiryDate;

	    @Min(value = 0, message = "Custom URL limit must be zero or positive")
	    private int customUrlLimit;

	    @ManyToOne
	    private User user;

	    @ManyToOne
	    private Plan plan;
}
