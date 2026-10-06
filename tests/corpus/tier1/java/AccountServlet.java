package corpus.tier1;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AccountServlet extends HttpServlet {
    private Connection connection;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String owner = request.getParameter("owner");
        try {
            Statement statement = connection.createStatement();
            ResultSet rs = statement.executeQuery("SELECT * FROM accounts WHERE owner = '" + owner + "'"); // fsb-expect: FSB-SQL-001
            rs.close();

            PreparedStatement safe = connection.prepareStatement("SELECT * FROM accounts WHERE owner = ?");
            safe.setString(1, owner);
            safe.executeQuery();

            int id = Integer.parseInt(request.getParameter("id"));
            statement.executeQuery("SELECT * FROM accounts WHERE id = " + id);
        } catch (Exception e) {
            response.sendError(500);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String report = request.getHeader("X-Report");
        Runtime.getRuntime().exec("/usr/bin/report " + report); // fsb-expect: FSB-CMD-001
        Runtime.getRuntime().exec(new String[] {"/usr/bin/report", "--daily"});
    }
}
