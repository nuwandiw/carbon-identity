package org.wso2.carbon.identity.application.authentication.endpoint.duo;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by nuwandi on 2/2/15.
 */
public class DuoLogin  extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException,
            IOException {

        if(request.getRequestURI().contains("/duo_login.do")){
            request.getRequestDispatcher("duoAuth.jsp").forward(request, response);
        }

    }
}
