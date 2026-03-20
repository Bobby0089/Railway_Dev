package com.aurionpro.service.admin;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.aurionpro.dto.admin.AdminRequestDto;
import com.aurionpro.dto.admin.AdminResponseDto;
import com.aurionpro.entity.Admin;
import com.aurionpro.exception.ApiException;
import com.aurionpro.repository.AdminRepository;

@Service
public class AdminServiceImpl implements AdminService{
	
	@Autowired
	private AdminRepository adminRepository;
	
	@Autowired
	private ModelMapper mapper;

	@Override
	public AdminResponseDto register(AdminRequestDto adminDto) {
		Admin admin = mapper.map(adminDto, Admin.class);
		adminRepository.save(admin);
		return mapper.map(admin, AdminResponseDto.class);
	}

	@Override
	public AdminResponseDto login(AdminRequestDto adminDto) {
		Admin admin = adminRepository.findByUsername(adminDto.getUsername())
				.orElseThrow(() -> new ApiException("Admin not found"));
		if (!admin.getPassword().equals(adminDto.getPassword())) {
	        throw new ApiException("Invalid password");
	    }
		return mapper.map(admin, AdminResponseDto.class);	
	}

	
}
