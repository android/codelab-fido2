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

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.util.Log
import androidx.annotation.WorkerThread
import androidx.core.content.edit
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.Transformations
import com.example.android.fido2.api.ApiException
import com.example.android.fido2.api.AuthApi
import com.example.android.fido2.api.Credential
import com.example.android.fido2.toBase64
import com.google.android.gms.fido.Fido
import com.google.android.gms.fido.fido2.Fido2ApiClient
import com.google.android.gms.fido.fido2.Fido2PendingIntent
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAssertionResponse
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAttestationResponse
import com.google.android.gms.tasks.Task
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
        private const val PREF_TOKEN = "token"
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

    /**
     * Stores a temporary challenge that needs to be memorized between request and response API
     * calls for credential registration and sign-in.
     */
    private var lastKnownChallenge: String? = null

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
                val token = prefs.getString(PREF_TOKEN, null)
                value = when {
                    username.isNullOrBlank() -> SignInState.SignedOut
                    token.isNullOrBlank() -> SignInState.SigningIn(username)
                    else -> SignInState.SignedIn(username, token)
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
                val result = api.username(username)
                prefs.edit(commit = true) {
                    putString(PREF_USERNAME, result)
                }
                invokeSignInStateListeners(SignInState.SigningIn(username))
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
            try {
                val token = api.password(username, password)
                prefs.edit(commit = true) { putString(PREF_TOKEN, token) }
                invokeSignInStateListeners(SignInState.SignedIn(username, token))
            } catch (e: ApiException) {
                Log.e(TAG, "Invalid login credentials", e)

                // start login over again
                prefs.edit(commit = true) {
                    remove(PREF_USERNAME)
                    remove(PREF_TOKEN)
                    remove(PREF_CREDENTIALS)
                }

                invokeSignInStateListeners(
                    SignInState.SignInError(e.message ?: "Invalid login credentials" ))
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
        return Transformations.map(prefs.liveStringSet(PREF_CREDENTIALS, emptySet())) { set ->
            parseCredentials(set)
        }
    }

    @WorkerThread
    private fun refreshCredentials() {
        val token = prefs.getString(PREF_TOKEN, null)!!
        prefs.edit(commit = true) {
            putStringSet(PREF_CREDENTIALS, api.getKeys(token).toStringSet())
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
     * Clears the sign-in token. The sign-in state will proceed to [SignInState.SigningIn].
     */
    fun clearToken() {
        executor.execute {
            val username = prefs.getString(PREF_USERNAME, null)!!
            prefs.edit(commit = true) {
                remove(PREF_TOKEN)
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
                remove(PREF_TOKEN)
                remove(PREF_CREDENTIALS)
            }
            invokeSignInStateListeners(SignInState.SignedOut)
        }
    }

    /**
     * Starts to register a new credential to the server. This should be called only when the
     * sign-in state is [SignInState.SignedIn].
     */
    fun registerRequest(processing: MutableLiveData<Boolean>): LiveData<Fido2PendingIntent> {
        val result = MutableLiveData<Fido2PendingIntent>()
        executor.execute {
            fido2ApiClient?.let { client ->
                processing.postValue(true)
                try {
                    val token = prefs.getString(PREF_TOKEN, null)!!
                    val (options, challenge) = api.registerRequest(token)
                    lastKnownChallenge = challenge
                    val task: Task<Fido2PendingIntent> = client.getRegisterIntent(options)
                    result.postValue(Tasks.await(task))
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
                val token = prefs.getString(PREF_TOKEN, null)!!
                val challenge = lastKnownChallenge!!
                val response = AuthenticatorAttestationResponse.deserializeFromBytes(
                    data.getByteArrayExtra(Fido.FIDO2_KEY_RESPONSE_EXTRA)!!
                )
                val credentialId = response.keyHandle.toBase64()
                val credentials = api.registerResponse(token, challenge, response)
                prefs.edit {
                    putStringSet(PREF_CREDENTIALS, credentials.toStringSet())
                    putString(PREF_LOCAL_CREDENTIAL_ID, credentialId)
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
                val token = prefs.getString(PREF_TOKEN, null)!!
                api.removeKey(token, credentialId)
                refreshCredentials()
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
    fun signinRequest(processing: MutableLiveData<Boolean>): LiveData<Fido2PendingIntent> {
        val result = MutableLiveData<Fido2PendingIntent>()
        executor.execute {
            fido2ApiClient?.let { client ->
                processing.postValue(true)
                try {
                    val username = prefs.getString(PREF_USERNAME, null)!!
                    val credentialId = prefs.getString(PREF_LOCAL_CREDENTIAL_ID, null)
                    val (options, challenge) = api.signinRequest(username, credentialId)
                    lastKnownChallenge = challenge
                    val task = client.getSignIntent(options)
                    result.postValue(Tasks.await(task))
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
                val challenge = lastKnownChallenge!!
                val response = AuthenticatorAssertionResponse.deserializeFromBytes(
                    data.getByteArrayExtra(Fido.FIDO2_KEY_RESPONSE_EXTRA)
                )
                val credentialId = response.keyHandle.toBase64()
                val (credentials, token) = api.signinResponse(username, challenge, response)
                prefs.edit(commit = true) {
                    putString(PREF_TOKEN, token)
                    putStringSet(PREF_CREDENTIALS, credentials.toStringSet())
                    putString(PREF_LOCAL_CREDENTIAL_ID, credentialId)
                }
                invokeSignInStateListeners(SignInState.SignedIn(username, token))
            } catch (e: ApiException) {
                Log.e(TAG, "Cannot call registerResponse", e)
            } finally {
                processing.postValue(false)
            }
        }
    }

}
