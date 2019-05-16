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

package com.example.android.fido2.ui.username

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MediatorLiveData
import androidx.lifecycle.MutableLiveData
import com.example.android.fido2.repository.AuthRepository

class UsernameViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = AuthRepository.getInstance(application)

    private val _sending = MutableLiveData<Boolean>()
    val sending: LiveData<Boolean>
        get() = _sending

    val username = MutableLiveData<String>()

    val nextEnabled = MediatorLiveData<Boolean>().apply {
        var sendingValue = _sending.value ?: false
        var usernameValue = username.value
        fun update() {
            value = !sendingValue && !usernameValue.isNullOrBlank()
        }
        addSource(_sending) {
            sendingValue = it
            update()
        }
        addSource(username) {
            usernameValue = it
            update()
        }
    }

    fun sendUsername() {
        val username = username.value
        if (username != null && username.isNotBlank()) {
            repository.username(username, _sending)
        }
    }

}
