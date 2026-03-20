package com.aurionpro.dto.PageResponse;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@AllArgsConstructor
@Data
public class PageResponseDto<T> {
	
	private List<T> content;
	private int pagesize;
	private int pagenumber;
	private int totalpages;
	private long totalelements;
	private boolean islast;

}
