package com.springboot.jwtauthentication.controller;

import java.util.HashSet;
import java.util.Set;

import javax.validation.Valid;
import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.Properties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import com.springboot.jwtauthentication.auth.request.LoginForm;
import com.springboot.jwtauthentication.auth.request.SignUpForm;
import com.springboot.jwtauthentication.auth.response.JwtResponse;
import com.springboot.jwtauthentication.auth.response.ResponseMessage;
import com.springboot.jwtauthentication.model.ConfirmationToken;
import com.springboot.jwtauthentication.model.Role;
import com.springboot.jwtauthentication.model.RoleName;
import com.springboot.jwtauthentication.model.User;
import com.springboot.jwtauthentication.repository.ConfirmationTokenRepository;
import com.springboot.jwtauthentication.repository.RoleRepository;
import com.springboot.jwtauthentication.repository.UserRepository;
import com.springboot.jwtauthentication.security.jwt.JwtProvider;
import com.springboot.jwtauthentication.security.services.EmailSenderService;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthRestAPIs {

	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserRepository userRepository;
	
	@Autowired
	private ConfirmationTokenRepository confirmationTokenRepository;
	
	@Autowired
	private EmailSenderService emailSenderService;


	@Autowired
	RoleRepository roleRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JwtProvider jwtProvider;

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginForm loginRequest) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);

		String jwt = jwtProvider.generateJwtToken(authentication);
		UserDetails userDetails = (UserDetails) authentication.getPrincipal();
		
		User user=userRepository.findByUsername(loginRequest.getUsername()).get();
		if(user.isEnabled()) {
			return ResponseEntity.ok(new JwtResponse(jwt, userDetails.getUsername(), userDetails.getAuthorities()));
		}
		else {
		
			return new ResponseEntity<>(new ResponseMessage("Login Fail : Please verify your Email account!"),
					HttpStatus.BAD_REQUEST);
		}
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpForm signUpRequest) {
		if (userRepository.existsByUsername(signUpRequest.getUsername())) {
			return new ResponseEntity<>(new ResponseMessage("Fail -> Username is already taken!"),
					HttpStatus.BAD_REQUEST);
		}

		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			return new ResponseEntity<>(new ResponseMessage("Fail -> Email is already in use!"),
					HttpStatus.BAD_REQUEST);
		}

		
		User user = new User(signUpRequest.getName(), signUpRequest.getUsername(), signUpRequest.getEmail(),
				encoder.encode(signUpRequest.getPassword()));

		Set<String> strRoles = signUpRequest.getRole();
		Set<Role> roles = new HashSet<>();

		strRoles.forEach(role -> {
			switch (role) {
			case "admin":
				Role adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN)
						.orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
				roles.add(adminRole);

				break;
			case "manager":
				Role managerRole = roleRepository.findByName(RoleName.ROLE_MANAGER)
						.orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
				roles.add(managerRole);

				break;
			default:
				Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
						.orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
				roles.add(userRole);
			}
		});

		user.setRoles(roles);
		userRepository.save(user);
		
		ConfirmationToken confirmationToken = new ConfirmationToken(user);
		
		confirmationTokenRepository.save(confirmationToken);
		
		
		final String username = "put_username_here";
        	final String password = "put_password_here";

        Properties prop = new Properties();
		
        prop.put("mail.smtp.host", "smtp.mailtrap.io");
        prop.put("mail.smtp.port", "2525");
        prop.put("mail.smtp.auth", "true");
        prop.put("mail.smtp.starttls.enable", "true");
        
        Session session = Session.getInstance(prop,
                new javax.mail.Authenticator() {
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(username, password);
                    }
                });

        try {

            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress("from@gmail.com"));
            message.setRecipients(
                    Message.RecipientType.TO,
                    InternetAddress.parse(signUpRequest.getEmail())
            );
            message.setSubject("Test Web Application Email Varification");

            message.setContent("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\r\n" + 
            		"<html xmlns=\"http://www.w3.org/1999/xhtml\">\r\n" + 
            		"<head>\r\n" + 
            		"  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\r\n" + 
            		"  <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />\r\n" + 
            		"  <title>Verify your email address</title>\r\n" + 
            		"  <style type=\"text/css\" rel=\"stylesheet\" media=\"all\">\r\n" + 
            		"    /* Base ------------------------------ */\r\n" + 
            		"    *:not(br):not(tr):not(html) {\r\n" + 
            		"      font-family: Arial, 'Helvetica Neue', Helvetica, sans-serif;\r\n" + 
            		"      -webkit-box-sizing: border-box;\r\n" + 
            		"      box-sizing: border-box;\r\n" + 
            		"    }\r\n" + 
            		"    body {\r\n" + 
            		"      width: 100% !important;\r\n" + 
            		"      height: 100%;\r\n" + 
            		"      margin: 0;\r\n" + 
            		"      line-height: 1.4;\r\n" + 
            		"      background-color: #F5F7F9;\r\n" + 
            		"      color: #839197;\r\n" + 
            		"      -webkit-text-size-adjust: none;\r\n" + 
            		"    }\r\n" + 
            		"    a {\r\n" + 
            		"      color: #414EF9;\r\n" + 
            		"    }\r\n" + 
            		"    /* Layout ------------------------------ */\r\n" + 
            		"    .email-wrapper {\r\n" + 
            		"      width: 100%;\r\n" + 
            		"      margin: 0;\r\n" + 
            		"      padding: 0;\r\n" + 
            		"      background-color: #F5F7F9;\r\n" + 
            		"    }\r\n" + 
            		"    .email-content {\r\n" + 
            		"      width: 100%;\r\n" + 
            		"      margin: 0;\r\n" + 
            		"      padding: 0;\r\n" + 
            		"    }\r\n" + 
            		"    /* Masthead ----------------------- */\r\n" + 
            		"    .email-masthead {\r\n" + 
            		"      padding: 25px 0;\r\n" + 
            		"      text-align: center;\r\n" + 
            		"    }\r\n" + 
            		"    .email-masthead_logo {\r\n" + 
            		"      max-width: 400px;\r\n" + 
            		"      border: 0;\r\n" + 
            		"    }\r\n" + 
            		"    .email-masthead_name {\r\n" + 
            		"      font-size: 16px;\r\n" + 
            		"      font-weight: bold;\r\n" + 
            		"      color: #839197;\r\n" + 
            		"      text-decoration: none;\r\n" + 
            		"      text-shadow: 0 1px 0 white;\r\n" + 
            		"    }\r\n" + 
            		"    /* Body ------------------------------ */\r\n" + 
            		"    .email-body {\r\n" + 
            		"      width: 100%;\r\n" + 
            		"      margin: 0;\r\n" + 
            		"      padding: 0;\r\n" + 
            		"      border-top: 1px solid #E7EAEC;\r\n" + 
            		"      border-bottom: 1px solid #E7EAEC;\r\n" + 
            		"      background-color: #FFFFFF;\r\n" + 
            		"    }\r\n" + 
            		"    .email-body_inner {\r\n" + 
            		"      width: 570px;\r\n" + 
            		"      margin: 0 auto;\r\n" + 
            		"      padding: 0;\r\n" + 
            		"    }\r\n" + 
            		"    .email-footer {\r\n" + 
            		"      width: 570px;\r\n" + 
            		"      margin: 0 auto;\r\n" + 
            		"      padding: 0;\r\n" + 
            		"      text-align: center;\r\n" + 
            		"    }\r\n" + 
            		"    .email-footer p {\r\n" + 
            		"      color: #839197;\r\n" + 
            		"    }\r\n" + 
            		"    .body-action {\r\n" + 
            		"      width: 100%;\r\n" + 
            		"      margin: 30px auto;\r\n" + 
            		"      padding: 0;\r\n" + 
            		"      text-align: center;\r\n" + 
            		"    }\r\n" + 
            		"    .body-sub {\r\n" + 
            		"      margin-top: 25px;\r\n" + 
            		"      padding-top: 25px;\r\n" + 
            		"      border-top: 1px solid #E7EAEC;\r\n" + 
            		"    }\r\n" + 
            		"    .content-cell {\r\n" + 
            		"      padding: 35px;\r\n" + 
            		"    }\r\n" + 
            		"    .align-right {\r\n" + 
            		"      text-align: right;\r\n" + 
            		"    }\r\n" + 
            		"    /* Type ------------------------------ */\r\n" + 
            		"    h1 {\r\n" + 
            		"      margin-top: 0;\r\n" + 
            		"      color: #292E31;\r\n" + 
            		"      font-size: 19px;\r\n" + 
            		"      font-weight: bold;\r\n" + 
            		"      text-align: left;\r\n" + 
            		"    }\r\n" + 
            		"    h2 {\r\n" + 
            		"      margin-top: 0;\r\n" + 
            		"      color: #292E31;\r\n" + 
            		"      font-size: 16px;\r\n" + 
            		"      font-weight: bold;\r\n" + 
            		"      text-align: left;\r\n" + 
            		"    }\r\n" + 
            		"    h3 {\r\n" + 
            		"      margin-top: 0;\r\n" + 
            		"      color: #292E31;\r\n" + 
            		"      font-size: 14px;\r\n" + 
            		"      font-weight: bold;\r\n" + 
            		"      text-align: left;\r\n" + 
            		"    }\r\n" + 
            		"    p {\r\n" + 
            		"      margin-top: 0;\r\n" + 
            		"      color: #839197;\r\n" + 
            		"      font-size: 16px;\r\n" + 
            		"      line-height: 1.5em;\r\n" + 
            		"      text-align: left;\r\n" + 
            		"    }\r\n" + 
            		"    p.sub {\r\n" + 
            		"      font-size: 12px;\r\n" + 
            		"    }\r\n" + 
            		"    p.center {\r\n" + 
            		"      text-align: center;\r\n" + 
            		"    }\r\n" + 
            		"    /* Buttons ------------------------------ */\r\n" + 
            		"    .button {\r\n" + 
            		"      display: inline-block;\r\n" + 
            		"      width: 200px;\r\n" + 
            		"      background-color: #414EF9;\r\n" + 
            		"      border-radius: 3px;\r\n" + 
            		"      color: #ffffff;\r\n" + 
            		"      font-size: 15px;\r\n" + 
            		"      line-height: 45px;\r\n" + 
            		"      text-align: center;\r\n" + 
            		"      text-decoration: none;\r\n" + 
            		"      -webkit-text-size-adjust: none;\r\n" + 
            		"      mso-hide: all;\r\n" + 
            		"    }\r\n" + 
            		"    .button--green {\r\n" + 
            		"      background-color: #28DB67;\r\n" + 
            		"    }\r\n" + 
            		"    .button--red {\r\n" + 
            		"      background-color: #FF3665;\r\n" + 
            		"    }\r\n" + 
            		"    .button--blue {\r\n" + 
            		"      background-color: #414EF9;\r\n" + 
            		"    }\r\n" + 
            		"    /*Media Queries ------------------------------ */\r\n" + 
            		"    @media only screen and (max-width: 600px) {\r\n" + 
            		"      .email-body_inner,\r\n" + 
            		"      .email-footer {\r\n" + 
            		"        width: 100% !important;\r\n" + 
            		"      }\r\n" + 
            		"    }\r\n" + 
            		"    @media only screen and (max-width: 500px) {\r\n" + 
            		"      .button {\r\n" + 
            		"        width: 100% !important;\r\n" + 
            		"      }\r\n" + 
            		"    }\r\n" + 
            		"  </style>\r\n" + 
            		"</head>\r\n" + 
            		"<body>\r\n" + 
            		"  <table class=\"email-wrapper\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\">\r\n" + 
            		"    <tr>\r\n" + 
            		"      <td align=\"center\">\r\n" + 
            		"        <table class=\"email-content\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\">\r\n" + 
            		"          <!-- Logo -->\r\n" + 
            		"          <tr>\r\n" + 
            		"            <td class=\"email-masthead\">\r\n" + 
            		"              <a class=\"email-masthead_name\">Test Web Application</a>\r\n" + 
            		"            </td>\r\n" + 
            		"          </tr>\r\n" + 
            		"          <!-- Email Body -->\r\n" + 
            		"          <tr>\r\n" + 
            		"            <td class=\"email-body\" width=\"100%\">\r\n" + 
            		"              <table class=\"email-body_inner\" align=\"center\" width=\"570\" cellpadding=\"0\" cellspacing=\"0\">\r\n" + 
            		"                <!-- Body content -->\r\n" + 
            		"                <tr>\r\n" + 
            		"                  <td class=\"content-cell\">\r\n" + 
            		"                    <h1>Verify your email address</h1>\r\n" + 
            		"                    <p>Thanks for signing up for Test Web Application! We're excited to have you as an early user.</p>\r\n" + 
            		"                    <!-- Action -->\r\n" + 
            		"                    <table class=\"body-action\" align=\"center\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\">\r\n" + 
            		"                      <tr>\r\n" + 
            		"                        <td align=\"center\">\r\n" + 
            		"                          <div>\r\n" + 
            		"                            <!--[if mso]><v:roundrect xmlns:v=\"urn:schemas-microsoft-com:vml\" xmlns:w=\"urn:schemas-microsoft-com:office:word\" href=\"{{action_url}}\" style=\"height:45px;v-text-anchor:middle;width:200px;\" arcsize=\"7%\" stroke=\"f\" fill=\"t\">\r\n" + 
            		"                            <v:fill type=\"tile\" color=\"#414EF9\" />\r\n" + 
            		"                            <w:anchorlock/>\r\n" + 
            		"                            <center style=\"color:#ffffff;font-family:sans-serif;font-size:15px;\">Verify Email</center>\r\n" + 
            		"                          </v:roundrect><![endif]-->\r\n" + 
            		"                            <a href=\"http://localhost:8080/confirm-account?token="+confirmationToken.getConfirmationToken()+"\" class=\"button button--blue\">Verify Email</a>\r\n" + 
            		"                          </div>\r\n" + 
            		"                        </td>\r\n" + 
            		"                      </tr>\r\n" + 
            		"                    </table>\r\n" + 
            		"                    <p>Thanks,<br>Test Web Application Tool Team</p>\r\n" + 
            		"                    <!-- Sub copy -->\r\n" + 
            		"                    <table class=\"body-sub\">\r\n" + 
            		"                      <tr>\r\n" + 
            		"                        <td>\r\n" + 
            		"                          <p class=\"sub\">If you are having trouble clicking the button, copy and paste the URL below into your web browser.\r\n" + 
            		"                          </p>\r\n" + 
            		"                          <p class=\"sub\"><a href=\"http://localhost:8080/services\">Support Team Test Web Application</a></p>\r\n" + 
            		"                        </td>\r\n" + 
            		"                      </tr>\r\n" + 
            		"                    </table>\r\n" + 
            		"                  </td>\r\n" + 
            		"                </tr>\r\n" + 
            		"              </table>\r\n" + 
            		"            </td>\r\n" + 
            		"          </tr>\r\n" + 
            		"          <tr>\r\n" + 
            		"            <td>\r\n" + 
            		"              <table class=\"email-footer\" align=\"center\" width=\"570\" cellpadding=\"0\" cellspacing=\"0\">\r\n" + 
            		"                <tr>\r\n" + 
            		"                  <td class=\"content-cell\">\r\n" + 
            		"                    <p class=\"sub center\">\r\n" + 
            		"                      Test Web Application\r\n" + 
            		"                      <br>All rights received\r\n" + 
            		"                    </p>\r\n" + 
            		"                  </td>\r\n" + 
            		"                </tr>\r\n" + 
            		"              </table>\r\n" + 
            		"            </td>\r\n" + 
            		"          </tr>\r\n" + 
            		"        </table>\r\n" + 
            		"      </td>\r\n" + 
            		"    </tr>\r\n" + 
            		"  </table>\r\n" + 
            		"</body>\r\n" + 
            		"</html>", "text/html");

            Transport.send(message);

            
            } catch (MessagingException e) {
               e.printStackTrace();
            }
		

		return new ResponseEntity<>(new ResponseMessage("User registered successfully!"), HttpStatus.OK);
	    }
	
	
	
}
