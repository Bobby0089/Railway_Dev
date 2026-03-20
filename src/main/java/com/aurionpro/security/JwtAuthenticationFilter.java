package com.aurionpro.security;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
// now we are creating our own filter before usernameandpasswordfilter 
public class JwtAuthenticationFilter extends OncePerRequestFilter {
	
	@Autowired
	private JwtTokenProvider jwtTokenProvider;

	@Autowired
	private UserDetailsService userDetailsService;

	@Override
	//this comes in third part
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		//get jwt token from http request
		String token = getTokenFromRequest(request);

		// validate token
		if (StringUtils.hasText(token) && jwtTokenProvider.validateToken(token)) {

			// get user name from token
			String username = jwtTokenProvider.getUsername(token);

			// load the user associated with token,This loads user information from the database.This uses UserDetailsService from Spring Security.
			UserDetails userDetails = userDetailsService.loadUserByUsername(username);

			//This creates an authentication object.It contains:
			//this we have creted to set in our application Context
			UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
					userDetails,//userDetails->logged in user
					null,//null->password (not needed here)
					userDetails.getAuthorities());//authorities->roles/permissions

			//This line adds extra information about the current HTTP request to the authentication object.
			//It creates an object called WebAuthenticationDetails and attaches it to the authenticationToken.
			//So the authentication now contains:User information,Roles/authorities,Request details
			authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			
			//Store Authentication in Security Context. Now Spring Security knows:who the user is, what roles they have,that they are logged in
			SecurityContextHolder.getContext().setAuthentication(authenticationToken);
		}
		
		//This passes the request to the next filter or controller.
		filterChain.doFilter(request, response);
	}

	private String getTokenFromRequest(HttpServletRequest request)
	{
		//Reads the Authorization header.
		String bearerToken = request.getHeader("Authorization");
		
		//Checks:not null, not empty, not only whitespace and Ensures the token follows the Bearer format.
		if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer "))
		{
			//Splits the string:Bearer token => into: ["Bearer", "token"] and .trim() Removes extra spaces.
			return bearerToken.split(" ")[1].trim();
		}
		return null;
	}

}
