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

package com.example.android.fido2.repository

import android.app.PendingIntent
import android.content.SharedPreferences
import android.util.Log
import androidx.core.content.edit
import androidx.lifecycle.asFlow
import androidx.lifecycle.map
import com.example.android.fido2.api.ApiException
import com.example.android.fido2.api.ApiResult
import com.example.android.fido2.api.AuthApi
import com.example.android.fido2.api.Credential
import com.google.android.gms.fido.fido2.Fido2ApiClient
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredential
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Works with the API, the local data store, and FIDO2 API.
 */
@Singleton
class AuthRepository @Inject constructor(
    private val api: AuthApi,
    private val prefs: SharedPreferences,
    private val scope: CoroutineScope
) {

    companion object {
        private const val TAG = "AuthRepository"

        // Keys for SharedPreferences
        private const val PREFS_NAME = "auth"
        private const val PREF_USERNAME = "username"
        private const val PREF_SESSION_ID = "session_id"
        private const val PREF_CREDENTIALS = "credentials"
        private const val PREF_LOCAL_CREDENTIAL_ID = "local_credential_id"
    }

    private var fido2ApiClient: Fido2ApiClient? = null

    fun setFido2APiClient(client: Fido2ApiClient?) {
        fido2ApiClient = client
    }

    private val signInStateMutable = MutableSharedFlow<SignInState>(
        replay = 1,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    val signInState = signInStateMutable.asSharedFlow()

    init {
        scope.launch {
            val username = prefs.getString(PREF_USERNAME, null)
            val sessionId = prefs.getString(PREF_SESSION_ID, null)
            val initialState = when {
                username.isNullOrBlank() -> SignInState.SignedOut
                sessionId.isNullOrBlank() -> SignInState.SigningIn(username)
                else -> SignInState.SignedIn(username)
            }
            signInStateMutable.emit(initialState)
        }
    }

    /**
     * Sends the username to the server. If it succeeds, the sign-in state will proceed to
     * [SignInState.SigningIn].
     */
    suspend fun username(username: String) {
        when (val result = api.username(username)) {
            ApiResult.SignedOutFromServer -> forceSignOut()
            is ApiResult.Success -> {
                prefs.edit(commit = true) {
                    putString(PREF_USERNAME, username)
                    putString(PREF_SESSION_ID, result.sessionId!!)
                }
                signInStateMutable.emit(SignInState.SigningIn(username))
            }
        }
    }

    /**
     * Signs in with a password. This should be called only when the sign-in state is
     * [SignInState.SigningIn]. If it succeeds, the sign-in state will proceed to
     * [SignInState.SignedIn].
     */
    suspend fun password(password: String) {
        val username = prefs.getString(PREF_USERNAME, null)!!
        val sessionId = prefs.getString(PREF_SESSION_ID, null)!!
        try {
            when (val result = api.password(sessionId, password)) {
                ApiResult.SignedOutFromServer -> forceSignOut()
                is ApiResult.Success -> {
                    prefs.edit(commit = true) {
                        result.sessionId?.let {
                            putString(PREF_SESSION_ID, it)
                        }
                    }
                    signInStateMutable.emit(SignInState.SignedIn(username))
                }
            }
        } catch (e: ApiException) {
            Log.e(TAG, "Invalid login credentials", e)

            // start login over again
            prefs.edit(commit = true) {
                remove(PREF_USERNAME)
                remove(PREF_SESSION_ID)
                remove(PREF_CREDENTIALS)
            }

            signInStateMutable.emit(
                SignInState.SignInError(e.message ?: "Invalid login credentials")
            )
        }
    }

    /**
     * Retrieves the list of credential this user has registered on the server. This should be
     * called only when the sign-in state is [SignInState.SignedIn].
     */
    fun getCredentials(): Flow<List<Credential>> {
        scope.launch {
            refreshCredentials()
        }
        return prefs.liveStringSet(PREF_CREDENTIALS, emptySet()).map { set ->
            parseCredentials(set)
        }.asFlow()
    }

    private suspend fun refreshCredentials() {
        val sessionId = prefs.getString(PREF_SESSION_ID, null)!!
        when (val result = api.getKeys(sessionId)) {
            ApiResult.SignedOutFromServer -> forceSignOut()
            is ApiResult.Success -> {
                prefs.edit(commit = true) {
                    result.sessionId?.let { putString(PREF_SESSION_ID, it) }
                    putStringSet(PREF_CREDENTIALS, result.data.toStringSet())
                }
            }
        }
    }

    private fun List<Credential>.toStringSet(): Set<String> {
        return mapIndexed { index, credential ->
            "$index;${credential.id};${credential.publicKey}"
        }.toSet()
    }

    private fun parseCredentials(set: Set<String>): List<Credential> {
        return set.map { s ->
            val (index, id, publicKey) = s.split(";")
            index to Credential(id, publicKey)
        }.sortedBy { (index, _) -> index }
            .map { (_, credential) -> credential }
    }

    /**
     * Clears the credentials. The sign-in state will proceed to [SignInState.SigningIn].
     */
    suspend fun clearCredentials() {
        val username = prefs.getString(PREF_USERNAME, null)!!
        prefs.edit(commit = true) {
            remove(PREF_CREDENTIALS)
        }
        signInStateMutable.emit(SignInState.SigningIn(username))
    }

    /**
     * Clears all the sign-in information. The sign-in state will proceed to
     * [SignInState.SignedOut].
     */
    suspend fun signOut() {
        prefs.edit(commit = true) {
            remove(PREF_USERNAME)
            remove(PREF_SESSION_ID)
            remove(PREF_CREDENTIALS)
        }
        signInStateMutable.emit(SignInState.SignedOut)
    }

    private suspend fun forceSignOut() {
        prefs.edit(commit = true) {
            remove(PREF_USERNAME)
            remove(PREF_SESSION_ID)
            remove(PREF_CREDENTIALS)
        }
        signInStateMutable.emit(SignInState.SignInError("Signed out from server."))
    }

    /**
     * Starts to register a new credential to the server. This should be called only when the
     * sign-in state is [SignInState.SignedIn].
     */
    suspend fun registerRequest(): PendingIntent? {
        fido2ApiClient?.let { client ->
            try {
                val sessionId = prefs.getString(PREF_SESSION_ID, null)!!

                // TODO(1): Call the server API: /registerRequest
                // - Use api.registerRequest to get an ApiResult of
                //   PublicKeyCredentialCreationOptions.
                // - Call fido2ApiClient.getRegisterIntent and create an intent to generate a
                //   new credential.
                // - Pass the intent back to the `result` LiveData so that the UI can open the
                //   fingerprint dialog.

            } catch (e: Exception) {
                Log.e(TAG, "Cannot call registerRequest", e)
            }
        }
        return null
    }

    /**
     * Finishes registering a new credential to the server. This should only be called after
     * a call to [registerRequest] and a local FIDO2 API for public key generation.
     */
    suspend fun registerResponse(credential: PublicKeyCredential) {
        try {
            val sessionId = prefs.getString(PREF_SESSION_ID, null)!!

            // TODO(3): Call the server API: /registerResponse
            // - Create an AuthenticatorAttestationResponse from the data intent generated by
            //   the fingerprint dialog.
            // - Use api.registerResponse to send the response back to the server.
            // - Save the returned list of credentials into the SharedPreferences. The key is
            //   PREF_CREDENTIALS.
            // - Also save the newly added credential ID into the SharedPreferences. The key is
            //   PREF_LOCAL_CREDENTIAL_ID. The ID can be obtained from the `keyHandle` field of
            //   the AuthenticatorAttestationResponse object.

        } catch (e: ApiException) {
            Log.e(TAG, "Cannot call registerResponse", e)
        }
    }

    /**
     * Removes a credential registered on the server.
     */
    suspend fun removeKey(credentialId: String) {
        try {
            val sessionId = prefs.getString(PREF_SESSION_ID, null)!!
            when (api.removeKey(sessionId, credentialId)) {
                ApiResult.SignedOutFromServer -> forceSignOut()
                is ApiResult.Success -> refreshCredentials()
            }
        } catch (e: ApiException) {
            Log.e(TAG, "Cannot call removeKey", e)
        }
    }

    /**
     * Starts to sign in with a FIDO2 credential. This should only be called when the sign-in state
     * is [SignInState.SigningIn].
     */
    suspend fun signinRequest(): PendingIntent? {
        fido2ApiClient?.let { client ->
            val sessionId = prefs.getString(PREF_SESSION_ID, null)!!
            val credentialId = prefs.getString(PREF_LOCAL_CREDENTIAL_ID, null)

            // TODO(4): Call the server API: /signinRequest
            // - Use api.signinRequest to get a PublicKeyCredentialRequestOptions.
            // - Call fido2ApiClient.getSignIntent and create an intent to assert the
            //   credential.
            // - Pass the intent to the `result` LiveData so that the UI can open the
            //   fingerprint dialog.

        }
        return null
    }

    /**
     * Finishes to signing in with a FIDO2 credential. This should only be called after a call to
     * [signinRequest] and a local FIDO2 API for key assertion.
     */
    suspend fun signinResponse(credential: PublicKeyCredential) {
        try {
            val username = prefs.getString(PREF_USERNAME, null)!!
            val sessionId = prefs.getString(PREF_SESSION_ID, null)!!

            // TODO(6): Call the server API: /signinResponse
            // - Create an AuthenticatorAssertionResponse from the data intent generated by
            //   the fingerprint dialog.
            // - Use api.signinResponse to send the response back to the server.
            // - Save the returned list of credentials into the SharedPreferences. The key is
            //   PREF_CREDENTIALS.
            // - Also save the credential ID into the SharedPreferences. The key is
            //   PREF_LOCAL_CREDENTIAL_ID. The ID can be obtained from the `keyHandle` field of
            //   the AuthenticatorAssertionResponse object.
            // - Notify the UI that the sign-in has succeeded. This can be done by calling
            //   `invokeSignInStateListeners(SignInState.SignedIn(username))`

        } catch (e: ApiException) {
            Log.e(TAG, "Cannot call registerResponse", e)
        }
    }

}
