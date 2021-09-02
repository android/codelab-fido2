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

package com.example.android.fido2.ui.home

import android.app.Activity
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.result.ActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.view.isVisible
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.lifecycleScope
import com.example.android.fido2.R
import com.example.android.fido2.databinding.HomeFragmentBinding
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch

@AndroidEntryPoint
class HomeFragment : Fragment(), DeleteConfirmationFragment.Listener {

    companion object {
        private const val TAG = "HomeFragment"
        private const val FRAGMENT_DELETE_CONFIRMATION = "delete_confirmation"
    }

    private val viewModel: HomeViewModel by viewModels()
    private lateinit var binding: HomeFragmentBinding

    private val createCredentialIntentLauncher = registerForActivityResult(
        ActivityResultContracts.StartIntentSenderForResult(),
        ::handleCreateCredentialResult
    )

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?, savedInstanceState: Bundle?
    ): View? {
        binding = HomeFragmentBinding.inflate(inflater, container, false)
        binding.lifecycleOwner = viewLifecycleOwner
        binding.viewModel = viewModel
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        val credentialAdapter = CredentialAdapter { credentialId ->
            DeleteConfirmationFragment.newInstance(credentialId)
                .show(childFragmentManager, FRAGMENT_DELETE_CONFIRMATION)
        }
        binding.credentials.adapter = credentialAdapter

        viewLifecycleOwner.lifecycleScope.launchWhenStarted {
            viewModel.credentials.collect { credentials ->
                credentialAdapter.submitList(credentials)
                binding.emptyCredentials.isVisible = credentials.isEmpty()
                binding.credentialsCaption.isVisible = credentials.isNotEmpty()
            }
        }

        // Menu
        binding.appBar.replaceMenu(R.menu.home)
        binding.appBar.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                R.id.action_reauth -> {
                    viewModel.reauth()
                    true
                }
                R.id.action_sign_out -> {
                    viewModel.signOut()
                    true
                }
                else -> false
            }
        }

        viewLifecycleOwner.lifecycleScope.launchWhenStarted {
            viewModel.processing.collect { processing ->
                if (processing) {
                    binding.processing.show()
                } else {
                    binding.processing.hide()
                }
            }
        }

        // FAB
        binding.add.setOnClickListener {
            lifecycleScope.launch {
                val intent = viewModel.registerRequest()
                if (intent != null) {

                    // TODO(2): Open the fingerprint dialog.
                    // - Open the fingerprint dialog by launching the intent from FIDO2 API.

                }
            }
        }
    }

    override fun onDeleteConfirmed(credentialId: String) {
        viewModel.removeKey(credentialId)
    }

    private fun handleCreateCredentialResult(activityResult: ActivityResult) {

        // TODO(3): Receive ActivityResult with the new Credential
        // - Extract byte array from result data using Fido.FIDO2_KEY_CREDENTIAL_EXTRA.
        // (continued below
        val bytes: ByteArray? = null

        when {
            activityResult.resultCode != Activity.RESULT_OK ->
                Toast.makeText(requireContext(), R.string.cancelled, Toast.LENGTH_SHORT).show()
            bytes == null ->
                Toast.makeText(requireContext(), R.string.credential_error, Toast.LENGTH_SHORT)
                    .show()
            else -> {

                // - Deserialize bytes into a PublicKeyCredential.
                // - Check if the response is an AuthenticationErrorResponse. If so, show a toast.
                // - Otherwise, pass the credential to the viewModel.

            }
        }
    }
}
