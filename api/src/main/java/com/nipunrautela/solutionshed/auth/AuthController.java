package com.nipunrautela.solutionshed.auth;

import com.nipunrautela.solutionshed.auth.dto.AuthRequest;
import com.nipunrautela.solutionshed.auth.dto.AuthResponse;
import com.nipunrautela.solutionshed.auth.dto.RegisterRequest;
import com.nipunrautela.solutionshed.auth.dto.UserResponse;
import com.nipunrautela.solutionshed.security.jwt.JwtService;
import com.nipunrautela.solutionshed.user.User;
import com.nipunrautela.solutionshed.user.UserService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Autowired
    public AuthController(
        UserService userService, 
        JwtService jwtService, 
        AuthenticationManager authenticationManager
    ) {
        this.userService = userService;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> registerUser(@RequestBody RegisterRequest registerRequest) {
        User user = User.builder()
                .userName(registerRequest.getUserName())
                .userEmail(registerRequest.getUserEmail())
                .userPassword(registerRequest.getUserPassword())
                .build();

        User savedUser = userService.registerUser(user);

        UserResponse userResponse = UserResponse.builder()
                .userId(savedUser.getUserId())
                .userName(savedUser.getUsername())
                .userEmail(savedUser.getUserEmail())
                .userRoles(savedUser.getUserRoles())
                .build();

        return ResponseEntity.ok(userResponse);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest authRequest) {
        System.out.println("AuthController: Login attempt for " + authRequest.getUsername());
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                        authRequest.getUsername(), 
                        authRequest.getPassword()
                    )
            );

            if (authentication.isAuthenticated()) {
                String accessToken = jwtService.generateJwt(authRequest.getUsername(), null);
                String refreshToken = jwtService.generateRefreshToken(authRequest.getUsername());
                long expiresIn = jwtService.getExpirationTime();

                return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken, expiresIn));
            } else {
                throw new RuntimeException("Authentication failed");
            }
        } catch (Exception e) {
            System.out.println("AuthController: Exception during login: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }
}
