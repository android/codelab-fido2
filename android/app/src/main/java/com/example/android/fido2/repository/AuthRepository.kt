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
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.util.Log
import androidx.annotation.WorkerThread
import androidx.core.content.edit
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.map
import com.example.android.fido2.api.ApiException
import com.example.android.fido2.api.ApiResult
import com.example.android.fido2.api.AuthApi
import com.example.android.fido2.api.Credential
import com.example.android.fido2.toBase64
import com.google.android.gms.fido.Fido
import com.google.android.gms.fido.fido2.Fido2ApiClient
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAssertionResponse
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAttestationResponse
import com.google.android.gms.tasks.Tasks
import java.util.concurrent.Executor
import java.util.concurrent.Executors

/**
 * Works with the API, the local data store, and FIDO2 API.
 */
class AuthRepository(
    private val api: AuthApi,
    private val prefs: SharedPreferences,
    private val executor: Executor
) {

    companion object {
        private const val TAG = "AuthRepository"

        // Keys for SharedPreferences
        private const val PREFS_NAME = "auth"
        private const val PREF_USERNAME = "username"
        private const val PREF_SESSION_ID = "session_id"
        private const val PREF_CREDENTIALS = "credentials"
        private const val PREF_LOCAL_CREDENTIAL_ID = "local_credential_id"

        private var instance: AuthRepository? = null

        fun getInstance(context: Context): AuthRepository {
            return instance ?: synchronized(this) {
                instance ?: AuthRepository(
                    AuthApi(),
                    context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE),
                    Executors.newFixedThreadPool(64)
                ).also { instance = it }
            }
        }
    }

    private var fido2ApiClient: Fido2ApiClient? = null

    fun setFido2APiClient(client: Fido2ApiClient?) {
        fido2ApiClient = client
    }

    private val signInStateListeners = mutableListOf<(SignInState) -> Unit>()

    private fun invokeSignInStateListeners(state: SignInState) {
        val listeners = signInStateListeners.toList() // Copy
        for (listener in listeners) {
            listener(state)
        }
    }

    /**
     * Returns the current sign-in state of the user. The UI uses this to navigate between screens.
     */
    fun getSignInState(): LiveData<SignInState> {
        return object : LiveData<SignInState>() {

            private val listener = { state: SignInState ->
                postValue(state)
            }

            init {
                val username = prefs.getString(PREF_USERNAME, null)
                val sessionId = prefs.getString(PREF_SESSION_ID, null)
                value = when {
                    username.isNullOrBlank() -> SignInState.SignedOut
                    sessionId.isNullOrBlank() -> SignInState.SigningIn(username)
                    else -> SignInState.SignedIn(username)
                }
            }

            override fun onActive() {
                signInStateListeners.add(listener)
            }

            override fun onInactive() {
                signInStateListeners.remove(listener)
            }
        }
    }

    /**
     * Sends the username to the server. If it succeeds, the sign-in state will proceed to
     * [SignInState.SigningIn].
     */
    fun username(username: String, sending: MutableLiveData<Boolean>) {
        executor.execute {
            sending.postValue(true)
            try {
                when (val result = api.username(username)) {
                    ApiResult.SignedOutFromServer -> forceSignOut()
                    is ApiResult.Success -> {
                        prefs.edit(commit = true) {
                            putString(PREF_USERNAME, username)
                            putString(PREF_SESSION_ID, result.sessionId!!)
                        }
                        invokeSignInStateListeners(SignInState.SigningIn(username))                    }
                }
            } finally {
                sending.postValue(false)
            }
        }
    }

    /**
     * Signs in with a password. This should be called only when the sign-in state is
     * [SignInState.SigningIn]. If it succeeds, the sign-in state will proceed to
     * [SignInState.SignedIn].
     *
     * @param processing The value is set to `true` while the API call is ongoing.
     */
    fun password(password: String, processing: MutableLiveData<Boolean>) {
        executor.execute {
            processing.postValue(true)
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
                        invokeSignInStateListeners(SignInState.SignedIn(username))
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

                invokeSignInStateListeners(
                    SignInState.SignInError(e.message ?: "Invalid login credentials")
                )
            } finally {
                processing.postValue(false)
            }
        }
    }

    /**
     * Retrieves the list of credential this user has registered on the server. This should be
     * called only when the sign-in state is [SignInState.SignedIn].
     */
    fun getCredentials(): LiveData<List<Credential>> {
        executor.execute {
            refreshCredentials()
        }
        return prefs.liveStringSet(PREF_CREDENTIALS, emptySet()).map { set ->
            parseCredentials(set)
        }
    }

    @WorkerThread
    private fun refreshCredentials() {
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
    fun clearCredentials() {
        executor.execute {
            val username = prefs.getString(PREF_USERNAME, null)!!
            prefs.edit(commit = true) {
                remove(PREF_CREDENTIALS)
            }
            invokeSignInStateListeners(SignInState.SigningIn(username))
        }
    }

    /**
     * Clears all the sign-in information. The sign-in state will proceed to
     * [SignInState.SignedOut].
     */
    fun signOut() {
        executor.execute {
            prefs.edit(commit = true) {
                remove(PREF_USERNAME)
                remove(PREF_SESSION_ID)
                remove(PREF_CREDENTIALS)
            }
            invokeSignInStateListeners(SignInState.SignedOut)
        }
    }

    private fun forceSignOut() {
        executor.execute {
            prefs.edit(commit = true) {
                remove(PREF_USERNAME)
                remove(PREF_SESSION_ID)
                remove(PREF_CREDENTIALS)
            }
            invokeSignInStateListeners(SignInState.SignInError("Signed out by server"))
        }
    }

    /**
     * Starts to register a new credential to the server. This should be called only when the
     * sign-in state is [SignInState.SignedIn].
     */
    fun registerRequest(processing: MutableLiveData<Boolean>): LiveData<PendingIntent?> {
        val result = MutableLiveData<PendingIntent>()
        executor.execute {
            fido2ApiClient?.let { client ->
                processing.postValue(true)
                try {
                    val sessionId = prefs.getString(PREF_SESSION_ID, null)!!
                    when (val apiResult = api.registerRequest(sessionId)) {
                        ApiResult.SignedOutFromServer -> forceSignOut()
                        is ApiResult.Success -> {
                            prefs.edit(commit = true) {
                                apiResult.sessionId?.let { putString(PREF_SESSION_ID, it) }
                            }
                            val task = client.getRegisterPendingIntent(apiResult.data)
                            result.postValue(Tasks.await(task))
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Cannot call registerRequest", e)
                } finally {
                    processing.postValue(false)
                }
            }
        }
        return result
    }

    /**
     * Finishes registering a new credential to the server. This should only be called after
     * a call to [registerRequest] and a local FIDO2 API for public key generation.
     */
    fun registerResponse(data: Intent, processing: MutableLiveData<Boolean>) {
        executor.execute {
            processing.postValue(true)
            try {
                val sessionId = prefs.getString(PREF_SESSION_ID, null)!!
                val response = AuthenticatorAttestationResponse.deserializeFromBytes(
                    data.getByteArrayExtra(Fido.FIDO2_KEY_RESPONSE_EXTRA)!!
                )
                val credentialId = response.keyHandle.toBase64()
                when (val result = api.registerResponse(sessionId, response)) {
                    ApiResult.SignedOutFromServer -> forceSignOut()
                    is ApiResult.Success -> {
                        prefs.edit {
                            result.sessionId?.let { putString(PREF_SESSION_ID, it) }
                            putStringSet(PREF_CREDENTIALS, result.data.toStringSet())
                            putString(PREF_LOCAL_CREDENTIAL_ID, credentialId)
                        }
                    }
                }
            } catch (e: ApiException) {
                Log.e(TAG, "Cannot call registerResponse", e)
            } finally {
                processing.postValue(false)
            }
        }
    }

    /**
     * Removes a credential registered on the server.
     */
    fun removeKey(credentialId: String, processing: MutableLiveData<Boolean>) {
        executor.execute {
            processing.postValue(true)
            try {
                val sessionId = prefs.getString(PREF_SESSION_ID, null)!!
                when (api.removeKey(sessionId, credentialId)) {
                    ApiResult.SignedOutFromServer -> forceSignOut()
                    is ApiResult.Success -> refreshCredentials()
                }
            } catch (e: ApiException) {
                Log.e(TAG, "Cannot call removeKey", e)
            } finally {
                processing.postValue(false)
            }
        }
    }

    /**
     * Starts to sign in with a FIDO2 credential. This should only be called when the sign-in state
     * is [SignInState.SigningIn].
     */
    fun signinRequest(processing: MutableLiveData<Boolean>): LiveData<PendingIntent?> {
        val result = MutableLiveData<PendingIntent?>()
        executor.execute {
            fido2ApiClient?.let { client ->
                processing.postValue(true)
                try {
                    val sessionId = prefs.getString(PREF_SESSION_ID, null)!!
                    val credentialId = prefs.getString(PREF_LOCAL_CREDENTIAL_ID, null)
                    if (credentialId != null) {
                        when (val apiResult = api.signinRequest(sessionId, credentialId)) {
                            ApiResult.SignedOutFromServer -> forceSignOut()
                            is ApiResult.Success -> {
                                val task = client.getSignPendingIntent(apiResult.data)
                                result.postValue(Tasks.await(task))
                            }
                        }
                    }
                } finally {
                    processing.postValue(false)
                }
            }
        }
        return result
    }

    /**
     * Finishes to signing in with a FIDO2 credential. This should only be called after a call to
     * [signinRequest] and a local FIDO2 API for key assertion.
     */
    fun signinResponse(data: Intent, processing: MutableLiveData<Boolean>) {
        executor.execute {
            processing.postValue(true)
            try {
                val username = prefs.getString(PREF_USERNAME, null)!!
                val sessionId = prefs.getString(PREF_SESSION_ID, null)!!
                val response = AuthenticatorAssertionResponse.deserializeFromBytes(
                    data.getByteArrayExtra(Fido.FIDO2_KEY_RESPONSE_EXTRA)
                )
                val credentialId = response.keyHandle.toBase64()
                when (val result = api.signinResponse(sessionId, response)) {
                    ApiResult.SignedOutFromServer -> forceSignOut()
                    is ApiResult.Success -> {
                        prefs.edit(commit = true) {
                            result.sessionId?.let { putString(PREF_SESSION_ID, it) }
                            putStringSet(PREF_CREDENTIALS, result.data.toStringSet())
                            putString(PREF_LOCAL_CREDENTIAL_ID, credentialId)
                        }
                        invokeSignInStateListeners(SignInState.SignedIn(username))
                    }
                }
            } catch (e: ApiException) {
                Log.e(TAG, "Cannot call registerResponse", e)
            } finally {
                processing.postValue(false)
            }
        }
    }

}
