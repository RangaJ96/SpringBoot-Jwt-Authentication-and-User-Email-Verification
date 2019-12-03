package com.springboot.jwtauthentication.controller;

import java.util.Properties;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;
import java.util.List;

import com.springboot.jwtauthentication.model.ConfirmationToken;
import com.springboot.jwtauthentication.model.User;
import com.springboot.jwtauthentication.repository.ConfirmationTokenRepository;
import com.springboot.jwtauthentication.repository.UserRepository;
import com.springboot.jwtauthentication.security.services.EmailSenderService;




@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
public class TestRestAPIs {
	
	@Autowired
	PasswordEncoder encoder;
	
	@Autowired
	UserRepository userRepository;
	
	@Autowired
	private ConfirmationTokenRepository confirmationTokenRepository;
	
	@Autowired
	private EmailSenderService emailSenderService;
	
	private User resetUser;

	
	@GetMapping("/users")
	@PreAuthorize("hasRole('ADMIN')")
    	public List<User> getUsers() {
        return (List<User>) userRepository.findAll();
    }
	
	@GetMapping("/users/{username}")
	@PreAuthorize("hasRole('ADMIN')")
    	public String blockUSer(@PathVariable String username) {
		System.out.println("Function call");
		User user=userRepository.findByUsername(username).get();
		user.setEnabled(false);
		userRepository.save(user);
        return "blocked";
    }
	
	@GetMapping("/finduser/{username}")
	@PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    	public User findById(@PathVariable String username){
		User user=userRepository.findByUsername(username).get();
        resetUser=user;
	ConfirmationToken confirmationToken = new ConfirmationToken(user);
		
		confirmationTokenRepository.save(confirmationToken);
		
		
		final String authUsername = "put_username";
        	final String password = "put_password";

        Properties prop = new Properties();
		
        prop.put("mail.smtp.host", "smtp.mailtrap.io");
        prop.put("mail.smtp.port", "2525");
        prop.put("mail.smtp.auth", "true");
        prop.put("mail.smtp.starttls.enable", "true");
        
        Session session = Session.getInstance(prop,
                new javax.mail.Authenticator() {
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(authUsername, password);
                    }
                });

        try {

            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress("from@gmail.com"));
            message.setRecipients(
                    Message.RecipientType.TO,
                    InternetAddress.parse(user.getEmail())
            );
            message.setSubject("Test Web Application Verify Email");
           
            
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
            		"                            <a href=\"http://localhost:8080/confirm-password?token="+confirmationToken.getConfirmationToken()+"\" class=\"button button--blue\">Verify Email</a>\r\n" + 
            		"                          </div>\r\n" + 
            		"                        </td>\r\n" + 
            		"                      </tr>\r\n" + 
            		"                    </table>\r\n" + 
            		"                    <p>Thanks,<br>Test Web Application Team</p>\r\n" + 
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
        return user;
    }
	
	@GetMapping("/user/changePassword/{password}")
	public String resetPassword(@PathVariable String password){
		this.resetUser.setPassword(encoder.encode(password));
		userRepository.save(this.resetUser);
		return ">>> Password change successfully";
	}
	
	@RequestMapping(value="/confirm-account", method= {RequestMethod.GET, RequestMethod.POST})
	public ModelAndView confirmUserAccount(ModelMap model, @RequestParam("token")String confirmationToken)
	{
		ConfirmationToken token = confirmationTokenRepository.findByConfirmationToken(confirmationToken);
		
		if(token != null)
		{
			User user = userRepository.findById(token.getUser().getId()).get();
			user.setEnabled(true);
			userRepository.save(user);
			
			model.addAttribute("attribute", "redirectWithRedirectPrefix");
	        return new ModelAndView("redirect:http://localhost:4200/auth/login", model);
		}
		else
		{
			model.addAttribute("attribute", "redirectWithRedirectPrefix");
	        return new ModelAndView("redirect:http://localhost:4200/errorPage", model);
		}
			
	}
	
	
	
	@RequestMapping(value="/confirm-password", method= {RequestMethod.GET, RequestMethod.POST})
	public ModelAndView confirmUserPassword(ModelMap model, @RequestParam("token")String confirmationToken)
	{
		ConfirmationToken token = confirmationTokenRepository.findByConfirmationToken(confirmationToken);
		
		if(token != null)
		{
			model.addAttribute("attribute", "redirectWithRedirectPrefix");
	        return new ModelAndView("redirect:http://localhost:4200/resetPassword", model);
		}
		else{
		model.addAttribute("attribute", "redirectWithRedirectPrefix");
        return new ModelAndView("redirect:http://localhost:4200/errorPage", model);
		}
	}
	
	
}
