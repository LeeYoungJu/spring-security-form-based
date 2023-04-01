package com.yjlee.springsecuritystudy.form;

import com.yjlee.springsecuritystudy.account.Account;
import com.yjlee.springsecuritystudy.account.AccountContext;
import com.yjlee.springsecuritystudy.common.SecurityLogger;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Collection;

@Service
public class SampleService {

    public void dashboard() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("==============");
        UserDetails principal = (UserDetails) authentication.getPrincipal();
        System.out.println(principal.getUsername());
    }

    @Async
    public void asyncService() {
        SecurityLogger.log("Async service is called");
    }
}
