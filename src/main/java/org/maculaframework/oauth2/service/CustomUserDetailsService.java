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
        userList.add(new User("macro", password, AuthorityUtils.commaSeparatedStringToAuthorityList("ADMIN,USER,ADMIN1,USER2,ADMIN3,USER4,ADMIN5,USER6,ADMIN7,USER8,ADMIN9,USER11,ADMIN111,USER22,ADMIN222,USER33,ADMIN33,USER333,ADMIN333,USER44,ADMIN44,USER444,ADMIN444,USER55,ADMIN55,USER555,ADMIN555,USER6,ADMIN6,USER66,ADMIN66,USER666,ADMIN666,A,B,C,D,E,F,G,H")));
        userList.add(new User("andy", password, AuthorityUtils.commaSeparatedStringToAuthorityList("ADMIN")));
        userList.add(new User("mark", password, AuthorityUtils.commaSeparatedStringToAuthorityList("USER")));
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
