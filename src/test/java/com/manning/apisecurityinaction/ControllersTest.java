package com.manning.apisecurityinaction;

import static org.junit.Assert.assertEquals;
import org.junit.Test;

import kong.unirest.*;

public class ControllersTest {
    @Test
    public void CreateUsersForTheDemo() {
        HttpResponse<JsonNode> response = Unirest.post("https://localhost:4567/users")
        .asJson(); 
        var responseStatus = response.getStatus();
        assertEquals(201, responseStatus);
    }
}