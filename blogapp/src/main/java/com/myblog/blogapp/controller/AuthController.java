package com.myblog.blogapp.controller;

import com.myblog.blogapp.entities.Role;
import com.myblog.blogapp.entities.User;
import com.myblog.blogapp.payload.LoginDto;
import com.myblog.blogapp.payload.SignUpDto;
import com.myblog.blogapp.repository.RoleRepository;
import com.myblog.blogapp.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Collection;
import java.util.Collections;

@Controller
@RequestMapping("/api/auth")
public class AuthController {
   //create method in config class otherwise it will not work
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private RoleRepository roleRepository;
    @PostMapping("/signin")
    public ResponseEntity<String> authenticateUser(@RequestBody LoginDto loginDto) {
        //its verify the username and password exist or not
        Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginDto.getUsernameOrEmail(),
                loginDto.getPassword()));
        //if username and password is correct its forward next step
        SecurityContextHolder.getContext().setAuthentication(authenticate);
        return new ResponseEntity<>("user signed-in successfully", HttpStatus.OK);
    }
    @PostMapping("/signup")
    public  ResponseEntity<?> registerUser(@RequestBody SignUpDto signUpDto){
        //check username exist or not
        if(userRepository.existByUsername(signUpDto.getUsername())){
            return new ResponseEntity<>("Username is already exist",HttpStatus.BAD_REQUEST);
        }
        //check email exist or not in DB
        if(userRepository.existByEmail(signUpDto.getEmail())){
            return new ResponseEntity<>("Email is already exist",HttpStatus.BAD_REQUEST);
        }
        //create user object
        User user=new User();
        user.setName(signUpDto.getName());
        user.setUsername(signUpDto.getUsername());
        user.setEmail(signUpDto.getEmail());
        user.setPassword(passwordEncoder.encode(signUpDto.getPassword()));
        //set the user in role As admin because i mention ROLE_ADMIN
        Role roles = roleRepository.findByName("ROLE_ADMIN").get();
        user.setRoles(Collections.singleton(roles));
        //register the user
        userRepository.save(user);
        return new ResponseEntity<>("Registration successfully",HttpStatus.OK);
    }
}
