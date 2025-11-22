package com.nipunrautela.solutionshed.auth.dto;

import com.nipunrautela.solutionshed.user.Role;
import lombok.Builder;
import lombok.Data;

import java.util.Set;

@Data
@Builder
public class UserResponse {
    private long userId;
    private String userName;
    private String userEmail;
    private Set<Role> userRoles;
}
