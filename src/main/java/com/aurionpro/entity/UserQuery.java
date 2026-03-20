package com.aurionpro.entity;

import java.time.LocalDateTime;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Entity
@Table(name = "userquerys")
@AllArgsConstructor
@RequiredArgsConstructor
@Data
public class UserQuery {

	@Id
	@GeneratedValue
	private int id;
	@ManyToOne
	private User user;
	private String queryText;
	private String status;
	private String responseText;
	private boolean resolved;
	private LocalDateTime createdAt;
	
	@PrePersist
	public void set() {
		this.createdAt=LocalDateTime.now();
		this.responseText="Not yet solved";
		this.resolved=false;
		this.status="Pending";
	}
}
