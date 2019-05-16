/*
 * Copyright 2019 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.android.fido2.api

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import com.google.common.truth.Truth.assertThat
import org.junit.Test
import org.junit.runner.RunWith

@LargeTest
@RunWith(AndroidJUnit4::class)
class AuthApiTest {

    val api = AuthApi()

    @Test
    fun username() {
        val result = api.username("wa")
        assertThat(result).isEqualTo("wa")
    }

    @Test
    fun password() {
        val result = api.password("wa", "o")
        assertThat(result).contains("signed-in=yes")
        assertThat(result).contains("username=wa")
    }

    @Test
    fun getKeys() {
        val token = api.password("wa", "o")
        val credentials = api.getKeys(token)
        assertThat(credentials).isEmpty()
        assertThat(api.getKeys(api.password("agektmr", "ajfda"))).isNotEmpty()
    }

    @Test
    fun registerRequest() {
        val token = api.password("wa", "o")
        val (result, _) = api.registerRequest(token)
        assertThat(result.user.displayName).isEqualTo("No name")
        assertThat(result.user.name).isEqualTo("wa")
        assertThat(result.excludeList).isEmpty()
        assertThat(result.authenticatorSelection?.attachment.toString()).isEqualTo("platform")
    }

}
