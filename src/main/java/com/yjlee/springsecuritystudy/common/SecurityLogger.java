package com.yjlee.springsecuritystudy.common;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityLogger {

    public static void log(String msg) {
        System.out.println(msg);
        Thread thread = Thread.currentThread();
        System.out.println("Thread: " + thread.getName());
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        System.out.println("Principal: " + principal);
    }
}
