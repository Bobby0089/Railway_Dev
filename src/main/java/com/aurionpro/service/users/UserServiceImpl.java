package com.aurionpro.service.users;

import java.util.ArrayList;
import java.util.List;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import com.aurionpro.dto.PageResponse.PageResponseDto;
import com.aurionpro.dto.user.AdminBlacklistUserResponseDto;
import com.aurionpro.dto.user.AdminUserResponseDto;
import com.aurionpro.dto.user.UserLoginDto;
import com.aurionpro.dto.user.UserRequestDto;
import com.aurionpro.dto.user.UserResponseDto;
import com.aurionpro.entity.ShortUrl;
import com.aurionpro.entity.User;
import com.aurionpro.entity.UserPlan;
import com.aurionpro.exception.ApiException;
import com.aurionpro.repository.UserRepository;

@Service
public class UserServiceImpl implements UserService {

	@Autowired
	private UserRepository userRepository;
	@Autowired
	private ModelMapper mapper;

	@Override
	public UserResponseDto register(UserRequestDto userDto) {
		User user = mapper.map(userDto, User.class);
		
		userRepository.save(user);
		
		return mapper.map(user, UserResponseDto.class);
	}

	@Override
	public UserResponseDto login(UserLoginDto userDto) {
		
		User user = userRepository.findByUsername(userDto.getUsername())
				.orElseThrow(() -> new ApiException("User not found"));
		if (!user.getPassword().equals(userDto.getPassword())) {
	        throw new ApiException("Invalid password");
	    }
		return mapper.map(user, UserResponseDto.class);
	}

	@Override
	public PageResponseDto<AdminUserResponseDto> getAllUsers(int pagenumber, int pagesize) {
		Pageable pageable = PageRequest.of(pagenumber, pagesize);

		Page<User> pageuser = userRepository.findAll(pageable);
		PageResponseDto<AdminUserResponseDto> pageResponseDto = new PageResponseDto<>();

		pageResponseDto.setPagenumber(pageuser.getNumber());
		pageResponseDto.setPagesize(pageuser.getSize());
		pageResponseDto.setTotalpages(pageuser.getTotalPages());
		pageResponseDto.setTotalelements(pageuser.getTotalElements());
		List<User> dbuser = pageuser.getContent();
		List<AdminUserResponseDto> dtoUsers = new ArrayList<>();
		for (User user : dbuser) {
			if(!user.isIsblacklist())
			{
				AdminUserResponseDto adminUserResponseDto= new AdminUserResponseDto();
				adminUserResponseDto.setId(user.getId());
				adminUserResponseDto.setUsername(user.getUsername());
				adminUserResponseDto.setFirstname(user.getFirstname());
				adminUserResponseDto.setLastname(user.getLastname());
				adminUserResponseDto.setEmail(user.getEmail());
				adminUserResponseDto.setPassword(user.getEmail());
				adminUserResponseDto.setIsblacklist(user.isIsblacklist());
				List<UserPlan> planlist = user.getUserPlans();
				List<String> planname = new ArrayList<>();
				for(UserPlan p:planlist) {
					String name = p.getPlan().getPlanname();
					planname.add(name);
				}
				adminUserResponseDto.setUserPlans(planname);
				List<ShortUrl> urllist = user.getShortUrls();
				List<String> urlname = new ArrayList<>();
				for(ShortUrl p:urllist) {
					String name = p.getShortCode();
					urlname.add(name);
				}
				adminUserResponseDto.setShortUrls(urlname);
				dtoUsers.add(adminUserResponseDto);
			}
		}
		pageResponseDto.setContent(dtoUsers);
		pageResponseDto.setIslast(pageuser.isLast());
		return pageResponseDto;
	}

	@Override
	public PageResponseDto<AdminBlacklistUserResponseDto> getAllBlackListedUsers(int pagenumber, int pagesize) {
		Pageable pageable = PageRequest.of(pagenumber, pagesize);

		Page<User> pageuser = userRepository.findAll(pageable);
		PageResponseDto<AdminBlacklistUserResponseDto> pageResponseDto = new PageResponseDto<>();

		pageResponseDto.setPagenumber(pageuser.getNumber());
		pageResponseDto.setPagesize(pageuser.getSize());
		pageResponseDto.setTotalpages(pageuser.getTotalPages());
		pageResponseDto.setTotalelements(pageuser.getTotalElements());
		List<User> dbuser = pageuser.getContent();
		List<AdminBlacklistUserResponseDto> dtoUsers = new ArrayList<>();
		for (User user : dbuser) {
			if(user.isIsblacklist())
			{
				AdminBlacklistUserResponseDto adminUserResponseDto= new AdminBlacklistUserResponseDto();
				adminUserResponseDto.setId(user.getId());
				adminUserResponseDto.setUsername(user.getUsername());
				adminUserResponseDto.setFirstname(user.getFirstname());
				adminUserResponseDto.setLastname(user.getLastname());
				adminUserResponseDto.setIsblacklist(user.isIsblacklist());
				dtoUsers.add(adminUserResponseDto);
			}
		}
		pageResponseDto.setContent(dtoUsers);
		pageResponseDto.setIslast(pageuser.isLast());
		return pageResponseDto;
	}

	@Override
	public long getTotalUser() {
		
		return userRepository.count();
	}

	@Override
	public UserResponseDto deactivateAUser(int userId) {
		
		User user = userRepository.findById(userId)
				.orElseThrow(() -> new ApiException("User not found"));
		
		user.setIsblacklist(true);
		userRepository.save(user);
		
		return  mapper.map(user, UserResponseDto.class);
	}

	@Override
	public UserResponseDto activateAUser(int userId) {
		User user = userRepository.findById(userId)
				.orElseThrow(() -> new ApiException("User not found"));
		
		user.setIsblacklist(false);
		userRepository.save(user);
		
		return  mapper.map(user, UserResponseDto.class);
	}

	@Override
	public UserResponseDto getAUser(String username) {
		User user = userRepository.findByUsername(username)
				.orElseThrow(() -> new ApiException("User not found"));
		
		return  mapper.map(user, UserResponseDto.class);
	}

}
