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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * <p>
 * <b>CustomClientDetailsService</b> Oauth2服务器的Client读取服务
 * </p>
 *
 * @author Rain
 * @since 2020-03-20
 */

public class CustomClientDetailsService implements ClientDetailsService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
        // TODO 从数据库读取Client信息
        BaseClientDetails clientDetails = new BaseClientDetails();

        clientDetails.setClientId(clientId);
        clientDetails.setClientSecret(passwordEncoder.encode("secret"));
        clientDetails.setAuthorizedGrantTypes(StringUtils.commaDelimitedListToSet("password,implicit,refresh_token,authorization_code"));
        clientDetails.setAccessTokenValiditySeconds(600_000_000);
        clientDetails.setRefreshTokenValiditySeconds(864_000_000);
        clientDetails.setScope(StringUtils.commaDelimitedListToSet("all"));
        clientDetails.setAuthorities(Collections.emptyList());
        Set<String> redirectUris = new HashSet<String>();
        redirectUris.add("http://baidu.com");
        clientDetails.setRegisteredRedirectUri(redirectUris);

        return clientDetails;
    }
}
