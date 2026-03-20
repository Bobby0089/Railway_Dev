package com.aurionpro.entity;

import java.time.LocalDateTime;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Entity
@Table(name="shorturls")
@AllArgsConstructor
@RequiredArgsConstructor
@Data
public class ShortUrl {
	
	 @Id
	    @GeneratedValue(strategy = GenerationType.IDENTITY)
	    private int id;

	    @NotBlank(message = "Original URL must not be blank")
	    private String originalUrl;

	    @NotBlank(message = "Short code must not be blank")
	    private String shortCode;

	    @Min(value = 0, message = "Total clicks must be zero or more")
	    private int totalClicks;

	    @NotNull(message = "CreatedAt timestamp is required")
	    private LocalDateTime createdAt;

	    @Min(value = 1, message = "Plan ID must be valid (greater than 0)")
	    private int planid;

	    private boolean customUrl;

	    @ManyToOne
	    private User user;

}
