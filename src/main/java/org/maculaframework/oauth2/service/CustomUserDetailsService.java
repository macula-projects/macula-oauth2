/*
 * Copyright 2004-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.maculaframework.oauth2.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * <p>
 * <b>CustomUserDetailsService</b> 自定义UserDetailsService
 * </p>
 *
 * @author Rain
 * @since 2020-03-21
 */

public class CustomUserDetailsService implements UserDetailsService {
    private List<User> userList;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public void initData() {
        String password = passwordEncoder.encode("123456");
        userList = new ArrayList<>();
        userList.add(new User("macro", password, AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_ADMIN,ROLE_USER,ROLE_ADMIN1,ROLE_USER2,ROLE_ADMIN3,ROLE_USER4,ROLE_ADMIN5,ROLE_USER6,ROLE_ADMIN7,ROLE_USER8,ROLE_ADMIN9,ROLE_USER11,ROLE_ADMIN111,ROLE_USER22,ROLE_ADMIN222,ROLE_USER33,ROLE_ADMIN33,ROLE_USER333,ROLE_ADMIN333,ROLE_USER44,ROLE_ADMIN44,ROLE_USER444,ROLE_ADMIN444,ROLE_USER55,ROLE_ADMIN55,ROLE_USER555,ROLE_ADMIN555,ROLE_USER6,ROLE_ADMIN6,ROLE_USER66,ROLE_ADMIN66,ROLE_USER666,ROLE_ADMIN666,ROLE_A,ROLE_B,ROLE_C,ROLE_D,ROLE_E,ROLE_F,ROLE_G,ROLE_H")));
        userList.add(new User("andy", password, AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_ADMIN")));
        userList.add(new User("mark", password, AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER")));
        userList.add(new User("client", passwordEncoder.encode("secret"), AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER")));
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // TODO 从数据库读取用户信息
        initData();
        List<User> findUserList = userList.stream().filter(user -> user.getUsername().equals(username)).collect(Collectors.toList());
        if (!CollectionUtils.isEmpty(findUserList)) {
            return findUserList.get(0);
        } else {
            throw new UsernameNotFoundException("用户名或密码错误");
        }
    }
}
