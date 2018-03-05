/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.sample.idp.mgt;

import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.log4j.Logger;
import org.wso2.carbon.authenticator.stub.AuthenticationAdminStub;
import org.wso2.carbon.authenticator.stub.LogoutAuthenticationExceptionException;
import org.wso2.carbon.identity.application.common.model.idp.xsd.Claim;
import org.wso2.carbon.identity.application.common.model.idp.xsd.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.idp.xsd.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.idp.xsd.IdentityProvider;
import org.wso2.carbon.idp.mgt.stub.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.rmi.RemoteException;
import java.util.Properties;

public class Client {
    private static AuthenticationAdminStub authstub;
    private static ConfigurationContext ctx;
    private static String serverUrl;
    private static String truststore;
    private static String truststorePassword;
    private static String authCookie;
    private static String username;
    private static String password;
    private static Properties properties;
    private static String remoteAddress;

    final static Logger log = Logger.getLogger(Client.class);

    public static void main(String[] args) throws IOException {
        properties = new Properties();
        loadConfiguration();

        ctx = ConfigurationContextFactory.createConfigurationContextFromFileSystem(null, null);
        String authEPR = serverUrl + "AuthenticationAdmin";
        String idpEPR = serverUrl + "IdentityProviderMgtService";
        System.setProperty("javax.net.ssl.trustStore", truststore);
        System.setProperty("javax.net.ssl.trustStorePassword", truststorePassword);
        authstub = new AuthenticationAdminStub(ctx, authEPR);
        try {
            login(username, password);
        } catch (Exception e) {
            log.error("Error while login");
        }

        IdentityProviderMgtServiceStub idpMgtStub = new IdentityProviderMgtServiceStub(ctx, idpEPR);
        ServiceClient idpClient = idpMgtStub._getServiceClient();
        Options options = idpClient.getOptions();
        options.setManageSession(true);
        options.setProperty(org.apache.axis2.transport.http.HTTPConstants.COOKIE_STRING, authCookie);

        try {
            addIDP(idpMgtStub);
            log.info("IdP added successfully");
        } catch (IdentityProviderMgtServiceIdentityProviderManagementExceptionException e) {
            log.error("Error while adding IdP");
        }
    }

    public static String login(String username, String password) throws Exception {
        boolean loggedIn = authstub.login(username, password, remoteAddress);
        if (loggedIn) {
            log.info("Logged in successfully");
            authCookie = (String) authstub._getServiceClient().getServiceContext().getProperty(
                    HTTPConstants.COOKIE_STRING);
        } else {
            log.error("Unsuccessful login attempt : " + username);
        }
        return authCookie;
    }

    private static void loadConfiguration() throws IOException {
        FileInputStream freader = new FileInputStream(Constants.PROPERTIES_FILE_NAME);
        properties.load(freader);

        serverUrl = properties.getProperty(Constants.REMOTE_SERVER_URL);
        remoteAddress = properties.getProperty(Constants.REMOTE_ADDRESS);
        username = properties.getProperty(Constants.USER_NAME);
        password = properties.getProperty(Constants.PASSWORD);
        truststore = Constants.RESOURCE_PATH + properties.getProperty(Constants.TRUST_STORE_PATH);
        truststorePassword = properties.getProperty(Constants.TRUST_STORE_PASSWORD);
    }

    public static void logout() throws RemoteException, LogoutAuthenticationExceptionException {
        authstub.logout();
    }

    public static void addIDP(IdentityProviderMgtServiceStub idpMgtStub)
            throws IdentityProviderMgtServiceIdentityProviderManagementExceptionException, RemoteException {
        IdentityProvider identityProvider = new IdentityProvider();
        ClaimMapping claimMapping;
        Claim claim;

        //Basic claim configurations
        identityProvider.setIdentityProviderName(properties.getProperty(Constants.IDP_NAME));
        identityProvider.setAlias(properties.getProperty(Constants.IDP_ALIAS));
        ClaimConfig claimConfig = new ClaimConfig();
        claimConfig.setLocalClaimDialect(true);
        claimConfig.setUserClaimURI(properties.getProperty(Constants.IDP_USER_CLAIM_URI));

        //Advanced claim configurations for IdP
        int numClaimMappings = Integer.parseInt(properties.getProperty(Constants.NUMBER_OF_CLAIM_MAPPINGS));
        for (int i = 1; i <= numClaimMappings; i++) {
            claim = new Claim();
            claim.setClaimUri(properties.getProperty(Constants.IDP_CLAIM_MAPPING + i + Constants._CLAIM_URI));
            claimMapping = new ClaimMapping();
            claimMapping.setLocalClaim(claim);
            claimMapping.setDefaultValue(properties.getProperty(Constants.IDP_CLAIM_MAPPING + i +
                    Constants._DEFAULT_VALUE));
            claimConfig.addClaimMappings(claimMapping);
        }
        identityProvider.setClaimConfig(claimConfig);
        idpMgtStub.addIdP(identityProvider);
    }
}
