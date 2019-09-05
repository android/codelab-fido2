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

package com.example.android.fido2

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import androidx.fragment.app.commit
import androidx.lifecycle.observe
import com.example.android.fido2.repository.SignInState
import com.example.android.fido2.ui.auth.AuthFragment
import com.example.android.fido2.ui.home.HomeFragment
import com.example.android.fido2.ui.username.UsernameFragment
import com.google.android.gms.fido.Fido
import com.google.android.gms.fido.fido2.api.common.AuthenticatorErrorResponse

class MainActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "MainActivity"
        const val REQUEST_FIDO2_REGISTER = 1
        const val REQUEST_FIDO2_SIGNIN = 2
    }

    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.main_activity)
        setSupportActionBar(findViewById(R.id.toolbar))

        viewModel.signInState.observe(this) { state ->
            when (state) {
                is SignInState.SignedOut -> {
                    showFragment(UsernameFragment::class.java) { UsernameFragment() }
                }
                is SignInState.SigningIn -> {
                    showFragment(AuthFragment::class.java) { AuthFragment() }
                }
                is SignInState.SignInError -> {
                    Toast.makeText(this, state.error, Toast.LENGTH_LONG).show()
                    // return to username prompt
                    showFragment(UsernameFragment::class.java) { UsernameFragment() }
                }
                is SignInState.SignedIn -> {
                    showFragment(HomeFragment::class.java) { HomeFragment() }
                }
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        when (requestCode) {
            REQUEST_FIDO2_REGISTER -> {
                val errorExtra = data?.getByteArrayExtra(Fido.FIDO2_KEY_ERROR_EXTRA)
                if (errorExtra != null) {
                    val error = AuthenticatorErrorResponse.deserializeFromBytes(errorExtra)
                    error.errorMessage?.let { errorMessage ->
                        Toast.makeText(this, errorMessage, Toast.LENGTH_LONG).show()
                        Log.e(TAG, errorMessage)
                    }
                } else if (resultCode != RESULT_OK) {
                    Toast.makeText(this, R.string.cancelled, Toast.LENGTH_SHORT).show()
                } else {
                    val fragment = supportFragmentManager.findFragmentById(R.id.container)
                    if (data != null && fragment is HomeFragment) {
                        fragment.handleRegister(data)
                    }
                }
            }
            REQUEST_FIDO2_SIGNIN -> {
                val errorExtra = data?.getByteArrayExtra(Fido.FIDO2_KEY_ERROR_EXTRA)
                if (errorExtra != null) {
                    val error = AuthenticatorErrorResponse.deserializeFromBytes(errorExtra)
                    error.errorMessage?.let { errorMessage ->
                        Toast.makeText(this, errorMessage, Toast.LENGTH_LONG).show()
                        Log.e(TAG, errorMessage)
                    }
                } else if (resultCode != RESULT_OK) {
                    Toast.makeText(this, R.string.cancelled, Toast.LENGTH_SHORT).show()
                } else {
                    val fragment = supportFragmentManager.findFragmentById(R.id.container)
                    if (data != null && fragment is AuthFragment) {
                        fragment.handleSignin(data)
                    }
                }
            }
            else -> super.onActivityResult(requestCode, resultCode, data)
        }
    }

    override fun onResume() {
        super.onResume()
        viewModel.setFido2ApiClient(Fido.getFido2ApiClient(this))
    }

    override fun onPause() {
        super.onPause()
        viewModel.setFido2ApiClient(null)
    }

    private fun showFragment(clazz: Class<out Fragment>, create: () -> Fragment) {
        val manager = supportFragmentManager
        if (!clazz.isInstance(manager.findFragmentById(R.id.container))) {
            manager.commit {
                replace(R.id.container, create())
            }
        }
    }

}
