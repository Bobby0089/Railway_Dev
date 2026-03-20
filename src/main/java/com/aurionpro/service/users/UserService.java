package com.aurionpro.service.users;

import com.aurionpro.dto.PageResponse.PageResponseDto;
import com.aurionpro.dto.user.AdminBlacklistUserResponseDto;
import com.aurionpro.dto.user.AdminUserResponseDto;
import com.aurionpro.dto.user.UserLoginDto;
import com.aurionpro.dto.user.UserRequestDto;
import com.aurionpro.dto.user.UserResponseDto;

public interface UserService {
	
	UserResponseDto register(UserRequestDto userDto);
	
	UserResponseDto login(UserLoginDto userDto);
	
	PageResponseDto<AdminUserResponseDto> getAllUsers(int pagenumber,int pagesize);
	
	PageResponseDto<AdminBlacklistUserResponseDto> getAllBlackListedUsers(int pagenumber,int pagesize);
	
	long getTotalUser();

	UserResponseDto deactivateAUser(int userId);

	UserResponseDto activateAUser(int userId);

	UserResponseDto getAUser(String username);

}
