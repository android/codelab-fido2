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
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import com.example.android.fido2.R
import com.example.android.fido2.databinding.AuthFragmentBinding
import com.example.android.fido2.ui.observeOnce
import com.google.android.gms.fido.Fido
import com.google.android.gms.fido.fido2.api.common.AuthenticatorErrorResponse

class AuthFragment : Fragment() {

    companion object {
        private const val TAG = "AuthFragment"
        const val REQUEST_FIDO2_SIGNIN = 2
    }

    private val viewModel: AuthViewModel by viewModels()
    private lateinit var binding: AuthFragmentBinding

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
        viewModel.processing.observe(viewLifecycleOwner) { processing ->
            if (processing) {
                binding.processing.show()
            } else {
                binding.processing.hide()
            }
        }
    }

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        viewModel.signinRequest().observeOnce(this) { intent ->
            startIntentSenderForResult(
                intent.intentSender,
                REQUEST_FIDO2_SIGNIN,
                null,
                0,
                0,
                0,
                null
            )
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == REQUEST_FIDO2_SIGNIN) {
            val errorExtra = data?.getByteArrayExtra(Fido.FIDO2_KEY_ERROR_EXTRA)
            if (errorExtra != null) {
                val error = AuthenticatorErrorResponse.deserializeFromBytes(errorExtra)
                error.errorMessage?.let { errorMessage ->
                    Toast.makeText(requireContext(), errorMessage, Toast.LENGTH_LONG).show()
                    Log.e(TAG, errorMessage)
                }
            } else if (resultCode != Activity.RESULT_OK) {
                Toast.makeText(requireContext(), R.string.cancelled, Toast.LENGTH_SHORT).show()
            } else {
                if (data != null) {
                    viewModel.signinResponse(data)
                }
            }

        } else {
            super.onActivityResult(requestCode, resultCode, data)
        }
    }
}
