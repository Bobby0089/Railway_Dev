package com.aurionpro.security;

import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.aurionpro.exception.UserApiException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtTokenProvider {

	@Value("${app.jwt-secret}")
	private String jwtSecret;
	
	@Value("${app.jwt-expiration-milliseconds}")
	private long jwtExpirationDate;
	
	public String generateToken(Authentication authentication)
	{
		String username = authentication.getName();
		
		
		Date currentdate = new Date();
		
		Date expireDate = new Date(currentdate.getTime() + jwtExpirationDate);
		
		
		// this comes in second part where we are creating a jwt token
		String token = Jwts.builder().claims()
				.subject(username)		// 1st we add a username 
				.issuedAt(new Date(System.currentTimeMillis()))	//2nd we will give issue time
				.expiration(expireDate)		// 3rd expire time
				.and()
				.signWith(key())		 //4th we will give a signature key a random string value
				.claim("role", authentication.getAuthorities())
				//.claim("id", )
				.compact(); // this compact will compact all of this and return a single string
		
		return token;
	}

	private SecretKey key() {
		
		return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));  // this is how we create a key and this is for signature verification
	}

	//This comes in part 3
	public boolean validateToken(String token)
	{
		 try {
			 //Jwts is a utility class from the JJWT library.It provides methods to: create JWT tokens, parse JWT tokens, verify signatures
		        Jwts
		        .parser() // read token This creates a JWT parser object.The parser is responsible for:reading the token,validating it,extracting the payload (claims)
		        .verifyWith(key()) //Use this secret key to verify the JWT signature.
		        .build() //This creates the final parser instance.
		        .parse(token); //This method parses the JWT token.
		        return true;
		    } catch (MalformedJwtException ex) {
		        throw new UserApiException(HttpStatus.BAD_REQUEST, "Invalid JWT token");
		    } catch (ExpiredJwtException ex) {
		        throw new UserApiException(HttpStatus.BAD_REQUEST, "Expired JWT token");
		    } catch (UnsupportedJwtException ex) {
		        throw new UserApiException(HttpStatus.BAD_REQUEST, "Unsupported JWT token");
		    } catch (IllegalArgumentException ex) {
		        throw new UserApiException(HttpStatus.BAD_REQUEST, "JWT claims string is empty.");
		    } catch (Exception e) {
		        throw new UserApiException(HttpStatus.BAD_REQUEST, "Invalid Credentials");
		    }
	}

	// this method extract username from token => third part
	public String getUsername(String token) {
		//Jwts is a class from the JWT library.parser() creates a JWT parser object.Create a parser that can read the JWT token.
		Claims claims = Jwts.parser()
						.verifyWith(key()) //This method tells the parser:Use this secret key to verify the token signature
						.build()  //This line builds the JWT parser.Now the parser is ready to:validate the token, read its content.
						.parseSignedClaims(token) //This method parses the JWT token.It performs several checks:Checks token format,Verifies signature using the secret key,Validates token structure
						//If token is invalid:❌ Exception will be thrown.If token is valid:✔ The token is decoded.
						.getPayload(); //✔ The token is decoded.The payload contains user information.getPayload() extracts this payload part.It returns a Claims object.
						//Claims represents the data stored inside the JWT payload.
		
		String	username = claims.getSubject();//getSubject() retrieves the subject claim (sub).
		
		return username;
	}
}
