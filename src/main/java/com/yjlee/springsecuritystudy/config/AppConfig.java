package com.yjlee.springsecuritystudy.config;

import com.yjlee.springsecuritystudy.account.Account;
import com.yjlee.springsecuritystudy.account.AccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class AppConfig {

    @Bean
    ApplicationRunner runner() {
        return new ApplicationRunner() {
            @Autowired
            AccountRepository accountRepository;

            @Autowired
            PasswordEncoder passwordEncoder;

            @Override
            public void run(ApplicationArguments args) throws Exception {
                Account account = Account.builder()
                        .username("yjlee")
                        .password(passwordEncoder.encode("123"))
                        .roles("USER")
                        .build();

                Account admin = Account.builder()
                        .username("admin")
                        .password(passwordEncoder.encode("123"))
                        .roles("ADMIN")
                        .build();

                System.out.println("-========== insert ==========");
                Account save = accountRepository.save(account);
                System.out.println(save.getPassword());

                accountRepository.save(admin);
            }
        };
    }

}
