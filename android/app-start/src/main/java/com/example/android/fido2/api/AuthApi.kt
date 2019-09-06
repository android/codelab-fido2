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

import android.util.JsonReader
import android.util.JsonToken
import android.util.JsonWriter
import com.example.android.fido2.BuildConfig
import com.example.android.fido2.decodeBase64
import com.example.android.fido2.toBase64
import com.google.android.gms.fido.fido2.api.common.Attachment
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAssertionResponse
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAttestationResponse
import com.google.android.gms.fido.fido2.api.common.AuthenticatorSelectionCriteria
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialDescriptor
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialParameters
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRequestOptions
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRpEntity
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialType
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialUserEntity
import okhttp3.MediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import okhttp3.ResponseBody
import java.io.StringReader
import java.io.StringWriter
import java.util.concurrent.TimeUnit

/**
 * Interacts with the server API.
 */
class AuthApi {

    companion object {
        private const val BASE_URL = BuildConfig.API_BASE_URL
        private val JSON = MediaType.parse("application/json")
    }

    private val client = OkHttpClient.Builder()
        .addInterceptor(AddHeaderInterceptor())
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(40, TimeUnit.SECONDS)
        .connectTimeout(40, TimeUnit.SECONDS)
        .build()

    /**
     * @param username The username to be used for sign-in.
     * @return The username.
     */
    fun username(username: String): String {
        val call = client.newCall(
            Request.Builder()
                .url("$BASE_URL/username")
                .method("POST", jsonRequestBody {
                    name("username").value(username)
                })
                .build()
        )
        val response = call.execute()
        if (!response.isSuccessful) {
            throwResponseError(response, "Error calling /username")
        }

        return parseUsername(findSetCookieInResponse(response, "username"))
    }

    /**
     * @param username The username sent to the server with `username()`.
     * @param password A password.
     * @return token The sign-in token to be used for subsequent API calls.
     */
    fun password(username: String, password: String): String {
        val call = client.newCall(
            Request.Builder()
                .url("$BASE_URL/password")
                .addHeader("Cookie", "username=$username")
                .method("POST", jsonRequestBody {
                    name("password").value(password)
                })
                .build()
        )
        val response = call.execute()
        if (!response.isSuccessful) {
            throwResponseError(response, "Error calling /password")
        }
        val cookie = findSetCookieInResponse(response, "signed-in")
        return "$cookie; username=$username"
    }

    /**
     * @param token The sign-in token.
     * @return A list of all the credentials registered on the server.
     */
    fun getKeys(token: String): List<Credential> {
        val call = client.newCall(
            Request.Builder()
                .url("$BASE_URL/getKeys")
                .addHeader("Cookie", token)
                .method("POST", jsonRequestBody {})
                .build()
        )
        val response = call.execute()
        if (!response.isSuccessful) {
            throwResponseError(response, "Error calling /getKeys")
        }
        val body = response.body() ?: throw ApiException("Empty response from /getKeys")
        return parseUserCredentials(body)
    }

    /**
     * @param token The sign-in token.
     * @return A pair. The `first` element is an [PublicKeyCredentialCreationOptions] that can be
     * used for a subsequent FIDO2 API call. The `second` element is a challenge string that should
     * be sent back to the server in [registerResponse].
     */
    fun registerRequest(token: String): Pair<PublicKeyCredentialCreationOptions, String> {
        val call = client.newCall(
            Request.Builder()
                .url("$BASE_URL/registerRequest")
                .addHeader("Cookie", token)
                .method("POST", jsonRequestBody {
                    name("attestation").value("none")
                    name("authenticatorSelection").objectValue {
                        name("authenticatorAttachment").value("platform")
                        name("userVerification").value("required")
                    }
                })
                .build()
        )
        val response = call.execute()
        if (!response.isSuccessful) {
            throwResponseError(response, "Error calling /registerRequest")
        }
        val body = response.body() ?: throw ApiException("Empty response from /registerRequest")
        return parsePublicKeyCredentialCreationOptions(body)
    }

    /**
     * @param token The sign-in token.
     * @param challenge The challenge string returned by [registerRequest].
     * @param response The FIDO2 response object.
     * @return A list of all the credentials registered on the server, including the newly
     * registered one.
     */
    fun registerResponse(
        token: String,
        challenge: String,
        response: AuthenticatorAttestationResponse
    ): List<Credential> {
        response.keyHandle.toBase64()

        val rawId = response.keyHandle.toBase64()
        val call = client.newCall(
            Request.Builder()
                .url("$BASE_URL/registerResponse")
                .addHeader("Cookie", "$token; challenge=$challenge")
                .method("POST", jsonRequestBody {
                    name("id").value(rawId)
                    name("type").value(PublicKeyCredentialType.PUBLIC_KEY.toString())
                    name("rawId").value(rawId)
                    name("response").objectValue {
                        name("clientDataJSON").value(
                            response.clientDataJSON.toBase64()
                        )
                        name("attestationObject").value(
                            response.attestationObject.toBase64()
                        )
                    }
                })
                .build()
        )
        val apiResponse = call.execute()
        if (!apiResponse.isSuccessful) {
            throwResponseError(apiResponse, "Error calling /registerResponse")
        }
        val body = apiResponse.body() ?: throw ApiException("Empty response from /registerResponse")
        return parseUserCredentials(body)
    }

    /**
     * @param token The sign-in token.
     * @param credentialId The credential ID to be removed.
     */
    fun removeKey(token: String, credentialId: String) {
        val call = client.newCall(
            Request.Builder()
                .url("$BASE_URL/removeKey?credId=$credentialId")
                .addHeader("Cookie", token)
                .method("POST", jsonRequestBody {})
                .build()
        )
        val response = call.execute()
        if (!response.isSuccessful) {
            throwResponseError(response, "Error calling /removeKey")
        }
        // Nothing useful in the response body; ignore.
    }

    /**
     * @param username The username to be used for the sign-in.
     * @param credentialId The credential ID of this device.
     * @return A pair. The `first` element is a [PublicKeyCredentialRequestOptions] that can be used
     * for a subsequent FIDO2 API call. The `second` element is a challenge string that should
     * be sent back to the server in [signinResponse].
     */
    fun signinRequest(
        username: String,
        credentialId: String?
    ): Pair<PublicKeyCredentialRequestOptions, String> {
        val call = client.newCall(
            Request.Builder()
                .url(
                    buildString {
                        append("$BASE_URL/signinRequest")
                        if (credentialId != null) {
                            append("?credId=$credentialId")
                        }
                    }
                )
                .addHeader("Cookie", "username=$username")
                .method("POST", jsonRequestBody {})
                .build()
        )
        val response = call.execute()
        if (!response.isSuccessful) {
            throwResponseError(response, "Error calling /signinRequest")
        }
        val body = response.body() ?: throw ApiException("Empty response from /signinRequest")
        return parsePublicKeyCredentialRequestOptions(body)
    }

    /**
     * @param username The username to be used for this sign-in.
     * @param challenge The challenge string returned by [signinRequest].
     * @param response The assertion response from FIDO2 API.
     */
    fun signinResponse(
        username: String,
        challenge: String,
        response: AuthenticatorAssertionResponse
    ): Pair<List<Credential>, String> {
        val rawId = response.keyHandle.toBase64()
        val call = client.newCall(
            Request.Builder()
                .url("$BASE_URL/signinResponse")
                .addHeader("Cookie", "username=$username; challenge=$challenge")
                .method("POST", jsonRequestBody {
                    name("id").value(rawId)
                    name("type").value(PublicKeyCredentialType.PUBLIC_KEY.toString())
                    name("rawId").value(rawId)
                    name("response").objectValue {
                        name("clientDataJSON").value(
                            response.clientDataJSON.toBase64()
                        )
                        name("authenticatorData").value(
                            response.authenticatorData.toBase64()
                        )
                        name("signature").value(
                            response.signature.toBase64()
                        )
                        name("userHandle").value(
                            response.userHandle?.toBase64() ?: ""
                        )
                    }
                })
                .build()
        )
        val apiResponse = call.execute()
        if (!apiResponse.isSuccessful) {
            throwResponseError(apiResponse, "Error calling /signingResponse")
        }
        val body = apiResponse.body() ?: throw ApiException("Empty response from /signinResponse")
        val cookie = findSetCookieInResponse(apiResponse, "signed-in")
        return parseUserCredentials(body) to "$cookie; username=$username"
    }

    private fun parsePublicKeyCredentialRequestOptions(
        body: ResponseBody
    ): Pair<PublicKeyCredentialRequestOptions, String> {
        val builder = PublicKeyCredentialRequestOptions.Builder()
        var challenge: String? = null
        JsonReader(body.byteStream().bufferedReader()).use { reader ->
            reader.beginObject()
            while (reader.hasNext()) {
                when (reader.nextName()) {
                    "challenge" -> {
                        val c = reader.nextString()
                        challenge = c
                        builder.setChallenge(c.decodeBase64())
                    }
                    "userVerification" -> reader.skipValue()
                    "allowCredentials" -> builder.setAllowList(parseCredentialDescriptors(reader))
                    "rpId" -> builder.setRpId(reader.nextString())
                    "timeout" -> builder.setTimeoutSeconds(reader.nextDouble())
                    else -> reader.skipValue()
                }
            }
            reader.endObject()
        }
        return builder.build() to challenge!!
    }

    private fun parsePublicKeyCredentialCreationOptions(
        body: ResponseBody
    ): Pair<PublicKeyCredentialCreationOptions, String> {
        val builder = PublicKeyCredentialCreationOptions.Builder()
        var challenge: String? = null
        JsonReader(body.byteStream().bufferedReader()).use { reader ->
            reader.beginObject()
            while (reader.hasNext()) {
                when (reader.nextName()) {
                    "user" -> builder.setUser(parseUser(reader))
                    "challenge" -> {
                        val c = reader.nextString()
                        builder.setChallenge(c.decodeBase64())
                        challenge = c
                    }
                    "pubKeyCredParams" -> builder.setParameters(parseParameters(reader))
                    "timeout" -> builder.setTimeoutSeconds(reader.nextDouble())
                    "attestation" -> reader.skipValue() // Unusedp
                    "excludeCredentials" -> builder.setExcludeList(
                        parseCredentialDescriptors(reader)
                    )
                    "authenticatorSelection" -> builder.setAuthenticatorSelection(
                        parseSelection(reader)
                    )
                    "rp" -> builder.setRp(parseRp(reader))
                }
            }
            reader.endObject()
        }
        return builder.build() to challenge!!
    }

    private fun parseRp(reader: JsonReader): PublicKeyCredentialRpEntity {
        var id: String? = null
        var name: String? = null
        reader.beginObject()
        while (reader.hasNext()) {
            when (reader.nextName()) {
                "id" -> id = reader.nextString()
                "name" -> name = reader.nextString()
                else -> reader.skipValue()
            }
        }
        reader.endObject()
        return PublicKeyCredentialRpEntity(id!!, name!!, /* icon */ null)
    }

    private fun parseSelection(reader: JsonReader): AuthenticatorSelectionCriteria {
        val builder = AuthenticatorSelectionCriteria.Builder()
        reader.beginObject()
        while (reader.hasNext()) {
            when (reader.nextName()) {
                "authenticatorAttachment" -> builder.setAttachment(
                    Attachment.fromString(reader.nextString())
                )
                "userVerification" -> reader.skipValue()
                else -> reader.skipValue()
            }
        }
        reader.endObject()
        return builder.build()
    }

    private fun parseCredentialDescriptors(
        reader: JsonReader
    ): List<PublicKeyCredentialDescriptor> {
        val list = mutableListOf<PublicKeyCredentialDescriptor>()
        reader.beginArray()
        while (reader.hasNext()) {
            var id: String? = null
            reader.beginObject()
            while (reader.hasNext()) {
                when (reader.nextName()) {
                    "id" -> id = reader.nextString()
                    "type" -> reader.skipValue()
                    "transports" -> reader.skipValue()
                    else -> reader.skipValue()
                }
            }
            reader.endObject()
            list.add(
                PublicKeyCredentialDescriptor(
                    PublicKeyCredentialType.PUBLIC_KEY.toString(),
                    id!!.decodeBase64(),
                    /* transports */ null
                )
            )
        }
        reader.endArray()
        return list
    }

    private fun parseUser(reader: JsonReader): PublicKeyCredentialUserEntity {
        reader.beginObject()
        var id: String? = null
        var name: String? = null
        var displayName = ""
        while (reader.hasNext()) {
            when (reader.nextName()) {
                "id" -> id = reader.nextString()
                "name" -> name = reader.nextString()
                "displayName" -> displayName = reader.nextString()
                else -> reader.skipValue()
            }
        }
        reader.endObject()
        return PublicKeyCredentialUserEntity(
            id!!.decodeBase64(),
            name!!,
            null, // icon
            displayName
        )
    }

    private fun parseParameters(reader: JsonReader): List<PublicKeyCredentialParameters> {
        val parameters = mutableListOf<PublicKeyCredentialParameters>()
        reader.beginArray()
        while (reader.hasNext()) {
            reader.beginObject()
            var type: String? = null
            var alg = 0
            while (reader.hasNext()) {
                when (reader.nextName()) {
                    "type" -> type = reader.nextString()
                    "alg" -> alg = reader.nextInt()
                    else -> reader.skipValue()
                }
            }
            reader.endObject()
            parameters.add(PublicKeyCredentialParameters(type!!, alg))
        }
        reader.endArray()
        return parameters
    }

    private fun jsonRequestBody(body: JsonWriter.() -> Unit): RequestBody {
        val output = StringWriter()
        JsonWriter(output).use { writer ->
            writer.beginObject()
            writer.body()
            writer.endObject()
        }
        return RequestBody.create(JSON, output.toString())
    }

    private fun parseUsername(cookie: String): String {
        val start = cookie.indexOf("username=")
        val end = cookie.indexOf(";")
        if (start < 0 || end < 0 || start + 9 >= end) {
            throw RuntimeException("Cannot parse the cookie")
        }
        return cookie.substring(start + 9, end)
    }

    private fun parseUserCredentials(body: ResponseBody): List<Credential> {
        fun readCredentials(reader: JsonReader): List<Credential> {
            val credentials = mutableListOf<Credential>()
            reader.beginArray()
            while (reader.hasNext()) {
                reader.beginObject()
                var id: String? = null
                var publicKey: String? = null
                while (reader.hasNext()) {
                    when (reader.nextName()) {
                        "credId" -> id = reader.nextString()
                        "publicKey" -> publicKey = reader.nextString()
                        else -> reader.skipValue()
                    }
                }
                reader.endObject()
                if (id != null && publicKey != null) {
                    credentials.add(Credential(id, publicKey))
                }
            }
            reader.endArray()
            return credentials
        }
        JsonReader(body.byteStream().bufferedReader()).use { reader ->
            reader.beginObject()
            while (reader.hasNext()) {
                val name = reader.nextName()
                if (name == "credentials") {
                    return readCredentials(reader)
                } else {
                    reader.skipValue()
                }
            }
            reader.endObject()
        }
        throw ApiException("Cannot parse credentials")
    }

    private fun throwResponseError(response: Response, message: String): Nothing {
        val b = response.body()
        if (b != null) {
            throw ApiException("$message; ${parseError(b)}")
        } else {
            throw ApiException(message)
        }
    }

    private fun parseError(body: ResponseBody): String {
        val errorString = body.string()
        try {
            JsonReader(StringReader(errorString)).use { reader ->
                reader.beginObject()
                while (reader.hasNext()) {
                    val name = reader.nextName()
                    if (name == "error") {
                        val token = reader.peek()
                        if (token == JsonToken.STRING) {
                            return reader.nextString()
                        }
                        return "Unknown"
                    } else {
                        reader.skipValue()
                    }
                }
                reader.endObject()
            }
        } catch (e: Exception) {
            throw ApiException("Cannot parse error: $errorString")
        }
        return "" // Don't throw; this method is called during throwing.
    }

    private fun JsonWriter.objectValue(body: JsonWriter.() -> Unit) {
        beginObject()
        body()
        endObject()
    }

    /*
     * Looks for a set-cookie header with a particular name
     */
    private fun findSetCookieInResponse(response: Response, cname: String): String {
        for (header in response.headers("set-cookie")) {
            if (header.startsWith("$cname=")) {
                return header
            }
        }
        throw ApiException("Cookie not found: $cname");
    }
}
