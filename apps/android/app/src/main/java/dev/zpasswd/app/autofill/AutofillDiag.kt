package dev.zpasswd.app.autofill

/**
 * 自动填充诊断日志：写 logcat（tag=zpasswd）并保留最近 50 条供设置页"自动填充诊断"展示。
 *
 * 独立成文件是为了让 [dev.zpasswd.app.biometric.DeviceAutoUnlock] 这类底层模块也能记日志，
 * 而不会把「自动填充服务」整个类拖进来形成循环依赖——本对象不依赖任何其他模块。
 */
object AutofillDiag {
    data class Event(val time: String, val msg: String)

    /** logcat 过滤用：adb logcat -s zpasswd */
    const val TAG = "zpasswd"

    private val events = ArrayDeque<Event>()

    fun log(msg: String) {
        val t = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)
            .format(java.util.Date())
        android.util.Log.i(TAG, "$t $msg")
        synchronized(events) {
            events.addLast(Event(t, msg))
            while (events.size > 50) events.removeFirst()
        }
    }

    fun snapshot(): List<Event> = synchronized(events) { events.toList().asReversed() }

    fun clear() = synchronized(events) { events.clear() }
}
