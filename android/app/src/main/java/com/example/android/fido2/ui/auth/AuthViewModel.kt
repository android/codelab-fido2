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

package com.example.android.fido2.ui.auth

import android.app.PendingIntent
import androidx.lifecycle.LiveData
import androidx.lifecycle.MediatorLiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.map
import com.example.android.fido2.repository.AuthRepository
import com.example.android.fido2.repository.SignInState
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredential
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject

@HiltViewModel
class AuthViewModel @Inject constructor(
    private val repository: AuthRepository
) : ViewModel() {

    val password = MutableLiveData<String>()

    private val _processing = MutableLiveData<Boolean>()
    val processing: LiveData<Boolean>
        get() = _processing

    private val _errorMessage = MutableLiveData<String>()
    val errorMessage: LiveData<String>
        get() = _errorMessage

    val signInEnabled = MediatorLiveData<Boolean>().apply {
        fun update(processing: Boolean, password: String) {
            value = !processing && password.isNotBlank()
        }
        addSource(_processing) { update(it, password.value ?: "") }
        addSource(password) { update(_processing.value == true, it) }
    }

    fun signinRequest(): LiveData<PendingIntent?> {
        return repository.signinRequest(_processing)
    }

    val currentUsername: LiveData<String> = repository.getSignInState().map { state ->
        when (state) {
            is SignInState.SigningIn -> state.username
            is SignInState.SignedIn -> state.username
            else -> "(user)"
        }
    }

    fun auth() {
        repository.password(password.value ?: "", _processing)
    }

    fun signinResponse(credential: PublicKeyCredential) {
        repository.signinResponse(credential, _processing)
    }

}
