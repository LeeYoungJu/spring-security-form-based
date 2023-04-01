package com.yjlee.springsecuritystudy.account;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SignUpControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    void signupForm() throws Exception {
        mockMvc.perform(get("/signup"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("_csrf")))
        ;
    }

    @Test
    void processSignup() throws Exception {
        mockMvc.perform(post("/signup")
                        .param("username", "tempuser")
                        .param("password", "123")
                        .with(csrf())
                )
                .andDo(print())
                .andExpect(status().is3xxRedirection())
        ;
    }

    @Test
    void processSignupWithoutCSRF() throws Exception {
        mockMvc.perform(post("/signup")
                        .param("username", "tempuser")
                        .param("password", "123")
                )
                .andDo(print())
                .andExpect(status().isForbidden())
        ;
    }
}