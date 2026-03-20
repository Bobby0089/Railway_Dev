package com.aurionpro.entity;

import com.aurionpro.enums.Type;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Entity
@Table(name="plans")
@AllArgsConstructor
@RequiredArgsConstructor
@Data
public class Plan {

	 @Id
	    @GeneratedValue(strategy = GenerationType.IDENTITY)
	    private int id;

	    @NotBlank(message = "Plan name is mandatory")
	    private String planname;

	    @NotNull(message = "Type is required")
	    private Type type;

	    @Min(value = 1, message = "URL limit must be at least 1")
	    private int urllimit;

	    @Min(value = 1, message = "Clicks per URL must be at least 1")
	    private int clicksperurl;

	    @Min(value = 0, message = "Custom URL limit cannot be negative")
	    private int customerlimit;

	    @Positive(message = "Price must be positive")
	    private double price;

	    private boolean isactive;

	    @PrePersist
	    public void set() {
	        this.isactive = true;
	    }
	
}
