package com.nipunrautela.solutionshed.auth.dto;

import lombok.Data;

@Data
public class RegisterRequest {
    private String userName;
    private String userEmail;
    private String userPassword;
}
