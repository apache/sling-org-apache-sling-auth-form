package org.apache.sling.auth.form.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.UUID;

import org.awaitility.Awaitility;
import org.junit.Before;
import org.junit.Test;

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/* TokenStore tests, incomplete for now */
 public class TokenStoreTest {
    private TokenStore store;
    private static final long SESSION_TIMEOUT_MSEC = 60 * 1000L;
    private static final long DEFAULT_EXPIRATION_TIME_MSEC = System.currentTimeMillis() + SESSION_TIMEOUT_MSEC / 2;
    private static final boolean DEFAULT_FAST_SEED = false;
    private static final String USER_ID = "user_" + UUID.randomUUID();
    private String encodedToken;
    private File tokenFile;
    private int additionalFileIndex;
    
    private File additionalTokenFile() {
        return new File(tokenFile.getParent(), tokenFile.getName() + "-" + additionalFileIndex++);
    }

    @Before
    public void setup() throws IOException, InvalidKeyException, NoSuchAlgorithmException, IllegalStateException {
        tokenFile = Files.createTempFile(getClass().getName(), "tokenstore").toFile();
        store = new TokenStore(tokenFile, SESSION_TIMEOUT_MSEC, DEFAULT_FAST_SEED);
        encodedToken = store.encode(DEFAULT_EXPIRATION_TIME_MSEC, USER_ID);
    }

    @Test
    public void validTokenTest() {
        assertTrue(store.isValid(encodedToken));
    }

    @Test
    public void invalidTokensTest() {
        final String [] invalid = {
            "1@21@3",
            "nothing",
            "0@bad@token"
        };
        for(String token : invalid) {
            assertFalse(store.isValid(token));
        }        
    }

    @Test
    public void expiredTokenTest() throws InvalidKeyException, IllegalStateException, NoSuchAlgorithmException {
        final String expired = store.encode(1, USER_ID);
        Awaitility.await("expiredToken")
            .atMost(Duration.ofSeconds(5))
            .pollDelay(Duration.ofMillis(50))
            .pollInterval(Duration.ofMillis(50))
            .until(() -> !store.isValid(expired));
        assertFalse(store.isValid(expired));
    }

    @Test
    public void loadTokenFileTest() throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException {
        final TokenStore newStore = new TokenStore(tokenFile, SESSION_TIMEOUT_MSEC, DEFAULT_FAST_SEED);
        assertTrue(newStore.isValid(encodedToken));

        final TokenStore emptyStore = new TokenStore(additionalTokenFile(), SESSION_TIMEOUT_MSEC, DEFAULT_FAST_SEED);
        assertFalse(emptyStore.isValid(encodedToken));
    }

    @Test
    public void encodingPartsTest() throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException {

        // Test with both a normal and "fast seed" store
        final TokenStore [] testStores = {
            new TokenStore(additionalTokenFile(), SESSION_TIMEOUT_MSEC, true),
            new TokenStore(additionalTokenFile(), SESSION_TIMEOUT_MSEC, false)
        };

        for(TokenStore testStore : testStores) {
            String lastHexNumber = "";
            for(int i=1 ; i < 100; i++) {
                final String uniqueUserId = "user-" + i;
                final String [] parts = TokenStore.split(testStore.encode(123, uniqueUserId));
    
                // First a unique large hex number
                assertNotEquals(parts[0], lastHexNumber);
                lastHexNumber = parts[0];
                new BigInteger(lastHexNumber, 16);
                assertTrue(lastHexNumber.length() > 20);
    
                // Then the timeout prefixed by something else
                assertEquals("123", parts[1].substring(1));
    
                // Then the user id
                assertEquals(uniqueUserId, parts[2]);
            }
        }
    }

    @Test(expected = NullPointerException.class)
    public void nullTokenFileTest() throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException {
        new TokenStore(null, SESSION_TIMEOUT_MSEC, DEFAULT_FAST_SEED);
    }
}
