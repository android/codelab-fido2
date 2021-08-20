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

package com.example.android.fido2.ui

import androidx.lifecycle.ViewModel
import com.example.android.fido2.repository.AuthRepository
import com.google.android.gms.fido.fido2.Fido2ApiClient
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject

@HiltViewModel
class MainViewModel @Inject constructor(
    private val repository: AuthRepository
) : ViewModel() {

    val signInState = repository.signInState

    fun setFido2ApiClient(client: Fido2ApiClient?) {
        repository.setFido2APiClient(client)
    }

}
