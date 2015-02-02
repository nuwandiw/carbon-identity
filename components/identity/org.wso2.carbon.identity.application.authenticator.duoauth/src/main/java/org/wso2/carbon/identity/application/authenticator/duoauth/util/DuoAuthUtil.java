package org.wso2.carbon.identity.application.authenticator.duoauth.util;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by nuwandi on 2/1/15.
 */
public class DuoAuthUtil {

    private static final String PROVISIONING_IDP = "IDP";
    private static final String PROVISIONING_TENANT = "TD";
    private static final String PROVISIONING_DOMAIN = "UD";
    private static final String PROVISIONING_USER = "UN";

    public String buildUserId(String username, String provisioningPattern,
                                 String separator, String idpName)
            throws IdentityProvisioningException {

        Map<String, String> provValues = new HashMap<String, String>();
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        String userStoreDomain = getDomainFromUserName(tenantAwareUsername);

        String provIdentifier = "";
        provValues.put(PROVISIONING_TENANT, tenantDomain.replaceAll(separator, ""));

        if (tenantAwareUsername != null) {
            provValues.put(PROVISIONING_USER, removeDomainFromUserName(tenantAwareUsername));
        }
        provValues.put(PROVISIONING_IDP, idpName.replaceAll(separator, ""));

        if (userStoreDomain != null) {
            provValues.put(PROVISIONING_DOMAIN, userStoreDomain.replaceAll(separator, ""));
        }

        String[] provisioningEntries = buildProvisioningEntries(provisioningPattern);

        for (int i = 0; i < provisioningEntries.length; i++) {
            if (!StringUtils.isEmpty(provisioningEntries[i])) {
                if (StringUtils.isEmpty(provIdentifier)) {
                    provIdentifier = provValues.get(provisioningEntries[i].trim());
                } else {
                    provIdentifier = provIdentifier.concat(separator)
                            .concat(provValues.get(provisioningEntries[i].trim()));
                }
            }
        }

        return provIdentifier.toLowerCase();
    }

    private String[] buildProvisioningEntries(String provisioningPattern)
            throws IdentityProvisioningException {

        if (!provisioningPattern.contains("{") || !provisioningPattern.contains("}")) {
            throw new IdentityProvisioningException("Invalid Provisioning Pattern");
        }

        String provisioningPatternWithoutCurlBrace = provisioningPattern
                .replaceAll("\\{", "").replaceAll("\\}", "");
        return provisioningPatternWithoutCurlBrace.split(",");
    }

    private String getDomainFromUserName(String username) {
        int index;
        if ((index = username.indexOf("/")) > 0) {
            String domain = username.substring(0, index);
            return domain;
        }
        return "PRIMARY";
    }

    private String removeDomainFromUserName(String username) {
        int index;
        if ((index = username.indexOf(CarbonConstants.DOMAIN_SEPARATOR)) >= 0) {
            // remove domain name if exist
            username = username.substring(index + 1);
        }
        return username;
    }
}
