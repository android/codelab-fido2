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

import android.app.Activity
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.widget.Toast
import androidx.activity.result.ActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.lifecycleScope
import com.example.android.fido2.R
import com.example.android.fido2.databinding.AuthFragmentBinding
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch

@AndroidEntryPoint
class AuthFragment : Fragment() {

    private val viewModel: AuthViewModel by viewModels()
    private lateinit var binding: AuthFragmentBinding

    private val signIntentLauncher = registerForActivityResult(
        ActivityResultContracts.StartIntentSenderForResult(),
        ::handleSignResult
    )

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        binding = AuthFragmentBinding.inflate(inflater, container, false)
        binding.lifecycleOwner = viewLifecycleOwner
        binding.viewModel = viewModel
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        binding.inputPassword.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_GO) {
                viewModel.submitPassword()
                true
            } else {
                false
            }
        }

        viewLifecycleOwner.lifecycleScope.launchWhenStarted {
            launch {
                viewModel.signinRequests.collect { intent ->

                    // TODO(6): Open the fingerprint dialog.
                    // - Open the fingerprint dialog by launching the intent from FIDO2 API.

                }
            }
            launch {
                viewModel.processing.collect { processing ->
                    if (processing) {
                        binding.processing.show()
                    } else {
                        binding.processing.hide()
                    }
                }
            }
        }
    }

    private fun handleSignResult(activityResult: ActivityResult) {

        // TODO(7): Handle the ActivityResult
        // - Extract byte array from result data using Fido.FIDO2_KEY_CREDENTIAL_EXTRA.
        // (continued below)
        val bytes: ByteArray? = null

        when {
            activityResult.resultCode != Activity.RESULT_OK ->
                Toast.makeText(requireContext(), R.string.cancelled, Toast.LENGTH_SHORT).show()
            bytes == null ->
                Toast.makeText(requireContext(), R.string.auth_error, Toast.LENGTH_SHORT).show()
            else -> {

                // - Deserialize bytes into a PublicKeyCredential.
                // - Check if the response is an AuthenticationErrorResponse. If so, show a toast.
                // - Otherwise, pass the credential to the viewModel.

            }
        }
    }
}
