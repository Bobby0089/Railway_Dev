package com.aurionpro.service.shoturl;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import com.aurionpro.controller.AdminController;
import com.aurionpro.dto.PageResponse.PageResponseDto;
import com.aurionpro.dto.shorturl.AdminShortUrlResponseDto;
import com.aurionpro.dto.shorturl.CustomUrlResponseDto;
import com.aurionpro.dto.shorturl.RenewRequestDto;
import com.aurionpro.dto.shorturl.ShortUrlRequestDto;
import com.aurionpro.dto.shorturl.ShortUrlResponseDto;
import com.aurionpro.dto.userQuery.AdminViewDto;
import com.aurionpro.entity.ShortUrl;
import com.aurionpro.entity.Url;
import com.aurionpro.entity.User;
import com.aurionpro.entity.UserPlan;
import com.aurionpro.entity.UserQuery;
import com.aurionpro.exception.ApiException;
import com.aurionpro.repository.ShortUrlRepository;
import com.aurionpro.repository.UrlRepository;
import com.aurionpro.repository.UserPlanRepository;
import com.aurionpro.repository.UserRepository;

@Service
public class ShortUrlServiceImpl implements ShortUrlService {

    @Autowired
    private ShortUrlRepository shortUrlRepo;

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private UserPlanRepository urlPlanRepo;
    
    @Autowired
    private UrlRepository urlRepository;
    
    @Autowired
    private UserRepository userRepository;

    @Override
    public ShortUrlResponseDto generateShortUrl(ShortUrlRequestDto request) {
        User user = userRepo.findById(request.getUserId())
                .orElseThrow(() -> new ApiException("User not found"));

        List<UserPlan> userplans = urlPlanRepo.findByPlanId(request.getPlanid());
        UserPlan userplan = new UserPlan();
        for(UserPlan p: userplans) {
        	userplan.setExpiryDate(p.getExpiryDate());
        	userplan.setId(p.getId());
        	userplan.setPlan(p.getPlan());
        	userplan.setRemainingClicks(p.getRemainingClicks());
        	userplan.setRemainingUrls(p.getRemainingUrls());
        	userplan.setCustomUrlLimit(p.getCustomUrlLimit());
        	userplan.setUser(p.getUser());
        }

//        if (userplan.getPlan().getId() != user.getUserPlans().get(request.getPlanid()).getId()) {
//            throw new ApiException("Plan does not belong to user");
//        }

        if (userplan.getRemainingUrls() <= 0) {
            throw new ApiException("URL limit exceeded for this plan");
        }

        Optional<ShortUrl> existingUrl = shortUrlRepo.findByOriginalUrlAndUserId(request.getOriginalUrl(), request.getUserId());
        if (existingUrl.isPresent()) {
            return new ShortUrlResponseDto(existingUrl.get().getShortCode());
        }

        String shortCode = UUID.randomUUID().toString().replace("-", "").substring(0, 8);

        ShortUrl shortUrl = new ShortUrl();
        shortUrl.setOriginalUrl(request.getOriginalUrl());
        shortUrl.setShortCode(shortCode);
        shortUrl.setCreatedAt(LocalDateTime.now());
        shortUrl.setTotalClicks(userplan.getRemainingClicks());
        shortUrl.setUser(user);
        shortUrl.setCustomUrl(false);
        shortUrl.setPlanid(request.getPlanid());
        
        Url url = new Url();
        url.setShorturl(shortCode);
        url.setIscustom(false);
        url.setClicksRemaining(userplan.getRemainingClicks());
        url.setPlanId(userplan.getPlan().getId());
        
        urlRepository.save(url);
        
        userplan.setRemainingUrls(userplan.getRemainingUrls() - 1);

        urlPlanRepo.save(userplan);
        shortUrlRepo.save(shortUrl);

        return new ShortUrlResponseDto(shortCode);
    }

	@Override
	public ShortUrlResponseDto generatecustomShortUrl(CustomUrlResponseDto request) {
		User user = userRepo.findById(request.getUserId())
                .orElseThrow(() -> new ApiException("User not found"));

		 List<UserPlan> userplans = urlPlanRepo.findByPlanId(request.getPlanid());
	        UserPlan userplan = new UserPlan();
	        for(UserPlan p: userplans) {
	        	userplan.setExpiryDate(p.getExpiryDate());
	        	userplan.setId(p.getId());
	        	userplan.setPlan(p.getPlan());
	        	userplan.setRemainingClicks(p.getRemainingClicks());
	        	userplan.setRemainingUrls(p.getRemainingUrls());
	        	userplan.setCustomUrlLimit(p.getCustomUrlLimit());
	        	userplan.setUser(p.getUser());
	        }

//	        if (userplan.getPlan().getId() != user.getUserPlans().get(userplan.getId()).getId()) {
//	            throw new ApiException("Plan does not belong to user");
//	        }

	        if (userplan.getRemainingUrls() <= 0) {
	            throw new ApiException("URL limit exceeded for this plan");
	        } 
	        
	        if (userplan.getCustomUrlLimit() <=0) {
	        	throw new ApiException("Custom Url limit exceeded for this plan");
	        }
	        
	        if (shortUrlRepo.existsByShortCode(request.getCustomUrl())) {
	            throw new ApiException("Short code already exists. Please try another.");
	        }

        Optional<ShortUrl> existingUrl = shortUrlRepo.findByOriginalUrlAndUserId(request.getOriginalUrl(), request.getUserId());
        if (existingUrl.isPresent()) {
            return new ShortUrlResponseDto(existingUrl.get().getShortCode());
        }

        ShortUrl shortUrl = new ShortUrl();
        shortUrl.setOriginalUrl(request.getOriginalUrl());
        shortUrl.setShortCode(request.getCustomUrl());
        shortUrl.setCreatedAt(LocalDateTime.now());
        shortUrl.setTotalClicks(0);
        shortUrl.setUser(user);
        shortUrl.setCustomUrl(true);
        shortUrl.setPlanid(request.getPlanid());

        userplan.setRemainingUrls(userplan.getRemainingUrls() - 1);
        userplan.setCustomUrlLimit(userplan.getCustomUrlLimit() - 1);
        
        Url url = new Url();
        url.setShorturl(request.getCustomUrl());
        url.setIscustom(true);
        url.setClicksRemaining(userplan.getRemainingClicks());
        url.setPlanId(userplan.getPlan().getId());
        
        urlRepository.save(url);

        urlPlanRepo.save(userplan);
        shortUrlRepo.save(shortUrl);

        return new ShortUrlResponseDto(request.getCustomUrl());
	}

	@Override
	public HttpStatus renewUrl(RenewRequestDto dto) {
		User user = userRepo.findById(dto.getUserId())
                .orElseThrow(() -> new ApiException("User not found"));
		
		List<UserPlan> userplans = urlPlanRepo.findByPlanId(dto.getPlanid());
        UserPlan userplan = new UserPlan();
        for(UserPlan p: userplans) {
        	userplan.setExpiryDate(p.getExpiryDate());
        	userplan.setId(p.getId());
        	userplan.setPlan(p.getPlan());
        	userplan.setRemainingClicks(p.getRemainingClicks());
        	userplan.setRemainingUrls(p.getRemainingUrls());
        	userplan.setCustomUrlLimit(p.getCustomUrlLimit());
        	userplan.setUser(p.getUser());
        }
        
        if (userplan.getRemainingUrls() <= 0) {
            throw new ApiException("URL limit exceeded for this plan");
        }
        
        Optional<Url> shorturl = urlRepository.findByShorturl(dto.getShorturl());
        Url url = urlRepository.findById(shorturl.get().getId())
        		.orElseThrow(() -> new ApiException("Short url not found"));
        
        url.setClicksRemaining(url.getClicksRemaining()+userplan.getRemainingClicks());
        
        userplan.setRemainingUrls(userplan.getRemainingUrls()-1);
        
        
        urlPlanRepo.save(userplan);
        urlRepository.save(url);
        
        
		return HttpStatus.ACCEPTED;
	}

	@Override
	public PageResponseDto<AdminShortUrlResponseDto> getAllUrls(int pagenumber, int pagesize) {
		Pageable pageable = PageRequest.of(pagenumber, pagesize);

		Page<ShortUrl> pageurl = shortUrlRepo.findAll(pageable);
		PageResponseDto<AdminShortUrlResponseDto> pageResponseDto = new PageResponseDto<>();

		pageResponseDto.setPagenumber(pageurl.getNumber());
		pageResponseDto.setPagesize(pageurl.getSize());
		pageResponseDto.setTotalpages(pageurl.getTotalPages());
		pageResponseDto.setTotalelements(pageurl.getTotalElements());
		List<ShortUrl> dbuserurl = pageurl.getContent();
		List<AdminShortUrlResponseDto> dtoUsersurl = new ArrayList<>();
		for (ShortUrl url : dbuserurl) {
			AdminShortUrlResponseDto dto = new AdminShortUrlResponseDto();
			dto.setCustomUrl(url.isCustomUrl());
			dto.setId(url.getId());
			dto.setOriginalUrl(url.getOriginalUrl());
			dto.setShortCode(url.getShortCode());
			dto.setName(url.getUser().getUsername());
			Url u = urlRepository.findByShorturl(url.getShortCode()).orElseThrow(()->new ApiException("url not found"));
			dto.setTotalclicks(u.getClicksRemaining());
			dtoUsersurl.add(dto);
			}
		pageResponseDto.setContent(dtoUsersurl);
		pageResponseDto.setIslast(pageurl.isLast());
		return pageResponseDto;
	}

	@Override
	public PageResponseDto<AdminShortUrlResponseDto> getUserUrl(int pageNumber, int pageSize, int userId) {
		
		Pageable pageable = PageRequest.of(pageNumber, pageSize);

		Page<ShortUrl> pageurl = shortUrlRepo.findAll(pageable);
		PageResponseDto<AdminShortUrlResponseDto> pageResponseDto = new PageResponseDto<>();

		pageResponseDto.setPagenumber(pageurl.getNumber());
		pageResponseDto.setPagesize(pageurl.getSize());
		pageResponseDto.setTotalpages(pageurl.getTotalPages());
		pageResponseDto.setTotalelements(pageurl.getTotalElements());
		List<ShortUrl> dbuserurl = pageurl.getContent();
		List<AdminShortUrlResponseDto> dtoUsersurl = new ArrayList<>();
		for (ShortUrl url : dbuserurl) {
			if(userId == url.getUser().getId()) {
				AdminShortUrlResponseDto dto = new AdminShortUrlResponseDto();
				dto.setCustomUrl(url.isCustomUrl());
				dto.setId(url.getId());
				dto.setOriginalUrl(url.getOriginalUrl());
				dto.setShortCode(url.getShortCode());
				dto.setName(url.getUser().getUsername());
				Url u = urlRepository.findByShorturl(url.getShortCode()).orElseThrow(()->new ApiException("url not found"));
				dto.setTotalclicks(u.getClicksRemaining());
				dtoUsersurl.add(dto);
			}
			}
		pageResponseDto.setContent(dtoUsersurl);
		pageResponseDto.setIslast(pageurl.isLast());
		return pageResponseDto;
	}

	@Override
	public long getTotalUrl() {
		
		return shortUrlRepo.count();
	}
}

