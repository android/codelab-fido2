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
import com.example.android.fido2.api.AuthApi
import com.example.android.fido2.api.Credential
import com.example.android.fido2.toBase64
import com.google.android.gms.fido.Fido
import com.google.android.gms.fido.fido2.Fido2ApiClient
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

    private var lastKnownChallenge: ByteArray? = null
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
                val result = api.username(username)
                prefs.edit(commit = true) {
                    putString(PREF_USERNAME, username)
                    putString(PREF_SESSION_ID, result.sessionId!!)
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
            val sessionId = prefs.getString(PREF_SESSION_ID, null)!!
            try {
                val result = api.password(sessionId, password)
                prefs.edit(commit = true) {
                    result.sessionId?.let {
                        putString(PREF_SESSION_ID, it)
                    }
                }
                invokeSignInStateListeners(SignInState.SignedIn(username))
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
        val result = api.getKeys(sessionId)
        prefs.edit(commit = true) {
            result.sessionId?.let { putString(PREF_SESSION_ID, it) }
            putStringSet(PREF_CREDENTIALS, result.data.toStringSet())
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

    /**
     * Starts to register a new credential to the server. This should be called only when the
     * sign-in state is [SignInState.SignedIn].
     */
    fun registerRequest(processing: MutableLiveData<Boolean>): LiveData<PendingIntent?> {
        val result = MutableLiveData<PendingIntent?>()
        executor.execute {
            fido2ApiClient?.let { client ->
                processing.postValue(true)
                try {
                    val sessionId = prefs.getString(PREF_SESSION_ID, null)!!

                    // TODO(1): Call the server API: /registerRequest
                    // - Use api.registerRequest to get an ApiResult of
                    //   PublicKeyCredentialCreationOptions.
                    // - Call fido2ApiClient.getRegisterIntent and create an intent to generate a
                    //   new credential.
                    // - Pass the intent back to the `result` LiveData so that the UI can open the
                    //   fingerprint dialog.
                    // Call the API.
                    val options = api.registerRequest(sessionId)
                    Log.v(TAG,   options.data.toString())
                    // Save the challenge.
                    lastKnownChallenge = options.data.challenge;
                    // Use getRegisterIntent to get an Intent to
                    // open the fingerprint dialog.
                    //val task: Task<Fido2PendingIntent>? = client.getRegisterIntent(options.data)
                    val task: Task<PendingIntent>? = client.getRegisterPendingIntent(options.data)
                    // Pass the Intent back to the UI.
                    result.postValue(task?.let { Tasks.await(it) })

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

                // TODO(3): Call the server API: /registerResponse
                // - Create an AuthenticatorAttestationResponse from the data intent generated by
                //   the fingerprint dialog.
                // - Use api.registerResponse to send the response back to the server.
                // - Save the returned list of credentials into the SharedPreferences. The key is
                //   PREF_CREDENTIALS.
                // - Also save the newly added credential ID into the SharedPreferences. The key is
                //   PREF_LOCAL_CREDENTIAL_ID. The ID can be obtained from the `keyHandle` field of
                //   the AuthenticatorAttestationResponse object.

                val challenge = lastKnownChallenge!!

                // Extract the AuthenticatorAttestationResponse.
                val response = AuthenticatorAttestationResponse.deserializeFromBytes(
                    data.getByteArrayExtra(Fido.FIDO2_KEY_RESPONSE_EXTRA)!!
                )

                // Memorize the credential ID.
                val credentialId = response.keyHandle.toBase64()
                // Call /auth/registerResponse.
                val credentials = api.registerResponse(sessionId, response )
                // Save the results.
                prefs.edit {
                    putStringSet(PREF_CREDENTIALS, credentials.data.toStringSet())
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
                val sessionId = prefs.getString(PREF_SESSION_ID, null)!!
                api.removeKey(sessionId, credentialId)
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
    fun signinRequest(processing: MutableLiveData<Boolean>): LiveData<PendingIntent?> {
        val result = MutableLiveData<PendingIntent?>()
        executor.execute {
            fido2ApiClient?.let { client ->
                processing.postValue(true)
                try {
                    val sessionId = prefs.getString(PREF_SESSION_ID, null)!!
                    val credentialId = prefs.getString(PREF_LOCAL_CREDENTIAL_ID, null)

                    // TODO(4): Call the server API: /signinRequest
                    // - Use api.signinRequest to get a PublicKeyCredentialRequestOptions.
                    // - Call fido2ApiClient.getSignIntent and create an intent to assert the
                    //   credential.
                    // - Pass the intent to the `result` LiveData so that the UI can open the
                    //   fingerprint dialog.
                    // Retrieve sign-in options from the server.
                    val publicKeyCredentialRequestOptions = api.signinRequest(sessionId, credentialId)
                    // Save the challenge string.
                    lastKnownChallenge = publicKeyCredentialRequestOptions.data.challenge
                    // Create an Intent to open the fingerprint dialog.
                    val task = client.getSignPendingIntent(publicKeyCredentialRequestOptions.data)
                    // Pass the Intent back to the UI.
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

                val challenge = lastKnownChallenge!!

                // Extract the AuthenticatorAssertionResponse.
                val response = AuthenticatorAssertionResponse.deserializeFromBytes(
                    data.getByteArrayExtra(Fido.FIDO2_KEY_RESPONSE_EXTRA)
                )
                // Save the credential ID.
                val credentialId = response.keyHandle.toBase64()
                // Send the information to the server
                val credentials = api.signinResponse(username, response)
                // Store the results.
                prefs.edit(commit = true) {
                    //putString(PREF_, token)
                    putStringSet(PREF_CREDENTIALS, credentials.data.toStringSet())
                    putString(PREF_LOCAL_CREDENTIAL_ID, credentialId)
                }
                // Let the UI know that the sign-in succeeded.
                invokeSignInStateListeners(SignInState.SignedIn(username))

            } catch (e: ApiException) {
                Log.e(TAG, "Cannot call registerResponse", e)
            } finally {
                processing.postValue(false)
            }
        }
    }

}
