package dev.zpasswd.app

import android.app.Application
import dev.zpasswd.app.data.VaultRepository

class ZpasswdApp : Application() {
    lateinit var repo: VaultRepository
        private set

    override fun onCreate() {
        super.onCreate()
        repo = VaultRepository.get(this)
    }
}
