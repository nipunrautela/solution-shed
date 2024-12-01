package com.nipunrautela.solutionshed.security.jwt;

import io.jsonwebtoken.Claims;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtData {
    private String subject;
    private String issuer;
    private Claims extraClaims;
    private Date expirationDate;
    private Date issueDate;
}
