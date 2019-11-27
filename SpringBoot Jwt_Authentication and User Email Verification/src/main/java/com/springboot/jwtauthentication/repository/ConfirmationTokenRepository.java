package com.springboot.jwtauthentication.repository;
import org.springframework.data.repository.CrudRepository;

import com.springboot.jwtauthentication.model.ConfirmationToken;



public interface ConfirmationTokenRepository extends CrudRepository<ConfirmationToken, String>{

	ConfirmationToken findByConfirmationToken(String confirmationToken);
}
