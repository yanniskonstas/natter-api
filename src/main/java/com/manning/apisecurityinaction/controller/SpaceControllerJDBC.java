package com.manning.apisecurityinaction.controller;
  
//import org.h2.jdbcx.*;
import org.json.*;
import spark.*;

import javax.sql.*;
import java.sql.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;;
//import java.time.*;
//import java.util.*;

public class SpaceControllerJDBC {    

    final boolean USEPREPAREDSTATEMENTS = true;
    final Logger logger = LoggerFactory.getLogger(SpaceController.class);
    private final DataSource datasource;

    public SpaceControllerJDBC(DataSource datasource) {
        this.datasource = datasource;
    }

    public JSONObject createSpace(Request request, Response response) throws SQLException {
        logger.info("Sun Ra says Space is the place!");
        var json = new JSONObject(request.body());
        var spaceName = json.getString("name");
        var owner = json.getString("owner");        

        try (var conn = datasource.getConnection();
                var stmt = conn.createStatement()) {
            conn.setAutoCommit(false);  

            var spaceId = firstLong(stmt.executeQuery("SELECT NEXT VALUE FOR space_id_seq;"));
            if (!USEPREPAREDSTATEMENTS) {
                // WARNING: this next line of code contains a security vulnerability!
                stmt.executeUpdate("INSERT INTO spaces(space_id, name, owner) VALUES(" + spaceId + ", '" + spaceName + "', '" + owner + "');");
                // It was replaced by using a prepared statement 
            } else {
                var insertStmt = conn.prepareStatement("INSERT INTO spaces(space_id, name, owner) VALUES(?, ?, ?);");
                insertStmt.setLong(1, spaceId); 
                insertStmt.setString(2, spaceName);
                insertStmt.setString(3, owner);
                insertStmt.executeUpdate();
            }

            conn.commit();

            response.status(201);
            response.header("Location", "/spaces/" + spaceId);

            return new JSONObject()
                .put("name", spaceName)
                .put("uri", "/spaces/" + spaceId);
        }
    }

    private static long firstLong(ResultSet resultSet)
        throws SQLException {
        if (!resultSet.next()) {
        throw new IllegalArgumentException("no results");
        }
        return resultSet.getLong(1);
    }
}