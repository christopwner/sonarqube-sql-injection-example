package com.root9b;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Scanner;
import java.util.logging.Logger;

/**
 * Demonstration of SonarQube only detecting vulnerability of in-line string
 * concatenation for executing queries.
 *
 * @author Christopher Towner
 */
public class SonarQubeSqlInjection {

    private static final String URL = "jdbc:derby:sonar;create=true";

    public static void main(String[] args) {
        try (Scanner scanner = new Scanner(System.in)) {
            Class.forName("org.apache.derby.jdbc.EmbeddedDriver").newInstance();
            createTable();

            System.out.print("User: ");
            String username = scanner.nextLine();
            System.out.print("Pass: ");
            String password = scanner.nextLine();

            detectedVulnerability(username, password);
        } catch (Exception e) {
            Logger.getGlobal().severe(e.getLocalizedMessage());
        }

        try {
            DriverManager.getConnection("jdbc:derby:sonar;shutdown=true");
        } catch (SQLException e) {
            //derby always throws exception on shutdown
        }
    }

    private static void createTable() {
        try (Connection connection = DriverManager.getConnection(URL);
                Statement statement = connection.createStatement()) {

            statement.execute("CREATE TABLE db_user (id INT PRIMARY KEY, username VARCHAR(20), password VARCHAR(20))");
            statement.execute("INSERT INTO db_user VALUES (1, 'admin', 'admin')");
            statement.execute("INSERT INTO db_user VALUES (2, 'user', 'pass')");
        } catch (SQLException e) {
            //ignore exceptions from table or rows existing
        }
    }

    /**
     * SonarQube will detect the vulnerability in this method.
     *
     * @param username
     * @param password
     */
    private static void detectedVulnerability(String username, String password) {
        try (Connection connection = DriverManager.getConnection(URL);
                Statement statement = connection.createStatement();
                ResultSet resultSet = statement.executeQuery("SELECT * FROM db_user WHERE username = '" + username + "' AND PASSWORD = '" + password + "'")) {

            if (!resultSet.next()) {
                throw new SecurityException("User name or password incorrect");
            }
        } catch (SecurityException | SQLException e) {
            Logger.getGlobal().info(e.getLocalizedMessage());
        }
    }

    /**
     * SonarQube will NOT detect vulnerability in this method.
     *
     * @param username
     * @param password
     */
    private static void undetectedVulnerability(String username, String password) {
        String sql = "SELECT * FROM db_user WHERE username = '" + username + "' AND PASSWORD = '" + password + "'";

        try (Connection connection = DriverManager.getConnection(URL);
                Statement statement = connection.createStatement();
                ResultSet resultSet = statement.executeQuery(sql)) {

            if (!resultSet.next()) {
                throw new SecurityException("User name or password incorrect");
            }
        } catch (SecurityException | SQLException e) {
            Logger.getGlobal().info(e.getLocalizedMessage());
        }
    }

}
