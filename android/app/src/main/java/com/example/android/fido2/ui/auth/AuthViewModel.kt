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

import android.app.Application
import android.content.Intent
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MediatorLiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.Transformations
import com.example.android.fido2.repository.AuthRepository
import com.example.android.fido2.repository.SignInState

class AuthViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = AuthRepository.getInstance(application)

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

    val signinIntent = repository.signinRequest(_processing)

    val currentUsername: LiveData<String> =
        Transformations.map(repository.getSignInState()) { state ->
            when (state) {
                is SignInState.SigningIn -> state.username
                is SignInState.SignedIn -> state.username
                else -> "(user)"
            }
        }

    fun auth() {
        repository.password(password.value ?: "", _processing)
    }

    fun signinResponse(data: Intent) {
        repository.signinResponse(data, _processing)
    }

}
