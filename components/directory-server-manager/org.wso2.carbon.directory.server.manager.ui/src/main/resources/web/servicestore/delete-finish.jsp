<!--
~ Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
~
~ WSO2 Inc. licenses this file to you under the Apache License,
~ Version 2.0 (the "License"); you may not use this file except
~ in compliance with the License.
~ You may obtain a copy of the License at
~
~ http://www.apache.org/licenses/LICENSE-2.0
~
~ Unless required by applicable law or agreed to in writing,
~ software distributed under the License is distributed on an
~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
~ KIND, either express or implied. See the License for the
~ specific language governing permissions and limitations
~ under the License.
-->
<%@taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@page import="org.apache.axis2.context.ConfigurationContext" %>
<%@page import="org.wso2.carbon.CarbonConstants" %>
<%@page import="org.wso2.carbon.ui.CarbonUIMessage" %>
<%@page import="org.wso2.carbon.ui.CarbonUIUtil" %>
<%@page import="org.wso2.carbon.utils.ServerConstants" %>
<%@page import="java.text.MessageFormat" %>
<%@page import="org.wso2.carbon.directory.server.manager.ui.DirectoryServerManagerClient" %>
<%@page import="org.wso2.carbon.ui.util.CharacterEncoder" %>

<%
    String servicePrincipleName = request.getParameter("spnName");

    String forwardTo = "index.jsp";

    String BUNDLE = "org.wso2.carbon.directory.server.manager.ui.i18n.Resources";
    ResourceBundle resourceBundle = ResourceBundle.getBundle(BUNDLE, request.getLocale());

    DirectoryServerManagerClient serverManager = null;

    try {

        serverManager = (DirectoryServerManagerClient) session.getAttribute(DirectoryServerManagerClient.
                SERVER_MANAGER_CLIENT);

        if (serverManager == null) {
            String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);
            String backEndServerURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
            ConfigurationContext configContext =
                    (ConfigurationContext) config.getServletContext().
                            getAttribute(CarbonConstants.CONFIGURATION_CONTEXT);

            serverManager = new DirectoryServerManagerClient(cookie, backEndServerURL, configContext);
            session.setAttribute(DirectoryServerManagerClient.SERVER_MANAGER_CLIENT, serverManager);
        }

        serverManager.removeServicePrinciple(servicePrincipleName);

        String message = MessageFormat.format(resourceBundle.getString("spn.deleted.success"),
                new Object[]{servicePrincipleName});
        CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.INFO, request);

    } catch (Exception e) {
        String message = MessageFormat.format(resourceBundle.getString(e.getMessage()),
                new Object[]{servicePrincipleName});
        CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.ERROR, request);
    }
%>



<%@page import="java.util.ResourceBundle" %>
<script type="text/javascript">
    function forward() {
        location.href = "<%=forwardTo%>";
    }
</script>

<script type="text/javascript">
    forward();
</script>
