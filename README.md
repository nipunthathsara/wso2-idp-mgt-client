##Sample Java client for WSO2 Identity Provider Management
###Configuring client.properties
####Authentication details
Add your client-truststore.jks file to the resources directory
* truststore.path=client-truststore.jks

Define your client trust store password
* truststore.password=wso2carbon

Define a user with sufficient permissions to add IdPs : user.name, user.password
* user.name=admin
* user.password=admin

####IdP details
* idp.name=testIdP
* idp.alias=https://localhost:9443/oauth2/token
#####Basic claim configurations :
* idp.userClaimURI=http://wso2.org/claims/emailaddress
#####Advanced claim configurations :
Define number of claim mappings to be added
* idp.claimMappings=2

Define multiple claim mappings with defaults values as below example
* idp.claimMapping1.claimURI=http://wso2.org/claims/dob
* idp.claimMapping1.defaultValue=somevalue1
* idp.claimMapping2.claimURI=http://wso2.org/claims/country
* idp.claimMapping2.defaultValue=somevalue2

###Build and run
* execute mvn clean install command from root
* Run the org.wso2.sample.idp.mgt.Client class