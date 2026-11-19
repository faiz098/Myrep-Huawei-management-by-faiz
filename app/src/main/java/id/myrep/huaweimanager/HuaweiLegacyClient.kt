package id.myrep.huaweimanager

import android.util.Base64
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.CookieHandler
import java.net.CookieManager
import java.net.CookiePolicy
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

class HuaweiLegacyClient(hostInput: String) {
    private val host = hostInput.trim().removePrefix("http://").removePrefix("https://").trimEnd('/')
    private val base = "http://" + host
    private val cookies = CookieManager(null, CookiePolicy.ACCEPT_ALL)
    private var sessionToken: String? = null
    init { CookieHandler.setDefault(cookies) }

    data class LoginResult(val success: Boolean, val message: String)
    data class WifiReadResult(val summary: String, val ssids: List<String>, val passwordFields: List<String>)
    private data class HttpResult(val code: Int, val body: String, val setCookie: List<String>, val type: String?)

    fun login(username: String, password: String): LoginResult {
        if (host.isBlank() || username.isBlank() || password.isBlank()) return LoginResult(false, "IP, username, dan password wajib diisi.")
        return try {
            cookies.cookieStore.removeAll()
            val tokenReply = request("/asp/GetRandCount.asp", "POST", null, true)
            val token = tokenReply.body.removePrefix("\uFEFF").trim()
            if (token.isBlank() || token.length > 256 || token.contains('<') || token.contains(' ')) {
                return LoginResult(false, "GAGAL PADA TOKEN LOGIN\nHTTP: " + tokenReply.code + "\nContent-Type: " + (tokenReply.type ?: "tidak ada") + "\nRespons: " + preview(tokenReply.body))
            }
            val encoded = Base64.encodeToString(password.toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP)
            val form = listOf("UserName" to username, "PassWord" to encoded, "Language" to "english", "x.X_HW_Token" to token)
                .joinToString("&") { (k, v) -> enc(k) + "=" + enc(v) }
            val reply = request("/login.cgi", "POST", form, true)
            val cookieNames = cookies.cookieStore.cookies.joinToString { it.name }.ifBlank { "tidak ada" }
            val cookieOk = cookies.cookieStore.cookies.any {
                (it.name.equals("Cookie", true) && it.value.contains("sid=", true) && !it.value.contains("id=-1", true)) ||
                (it.name.equals("sid", true) && it.value.isNotBlank())
            }
            val headerOk = reply.setCookie.any { it.contains("sid=", true) && !it.contains("id=-1", true) }
            if (cookieOk || headerOk) {
                sessionToken = try {
                    request("/html/ssmp/common/GetRandToken.asp", "GET", null, false).body.removePrefix("\uFEFF").trim().takeIf { it.isNotBlank() && !it.contains('<') }
                } catch (_: Exception) { null }
                LoginResult(true, "LOGIN BERHASIL\nToken: HTTP " + tokenReply.code + "\nLogin: HTTP " + reply.code + "\nCookie sesi: terdeteksi\nToken lanjutan: " + if (sessionToken == null) "belum tersedia" else "tersedia")
            } else {
                val why = when {
                    reply.code in 300..399 -> "Router mengalihkan permintaan login."
                    reply.body.contains("wrong password", true) || reply.body.contains("invalid", true) -> "Router memberi indikasi akun ditolak."
                    else -> "Cookie sesi autentikasi tidak ditemukan."
                }
                val headers = reply.setCookie.joinToString { it.substringBefore(';').substringBefore('=') + "=***" }.ifBlank { "tidak ada" }
                LoginResult(false, "LOGIN BELUM BERHASIL\nTahap token: HTTP " + tokenReply.code + ", " + token.length + " karakter\nTahap login: HTTP " + reply.code + "\nSet-Cookie: " + headers + "\nCookie tersimpan: " + cookieNames + "\nAnalisis: " + why + "\nRespons: " + preview(reply.body) + "\nPassword dan nilai cookie disembunyikan.")
            }
        } catch (e: Exception) {
            LoginResult(false, "LOGIN ERROR\n" + e.javaClass.simpleName + ": " + (e.message ?: "tidak ada detail") + "\nPeriksa WiFi dan alamat router.")
        }
    }

    fun readWifiSettings(): WifiReadResult {
        val paths = listOf("/html/bbsp/wlan/wlanbasic.asp", "/html/amp/wlanbasic/wlan.asp", "/html/amp/wlanbasic/WlanBasic.asp", "/html/bbsp/wlan/wlan.asp")
        val ssids = linkedSetOf<String>()
        val keys = linkedSetOf<String>()
        val details = paths.map { path ->
            try {
                val r = request(path, "GET", null, false)
                if (r.code in 200..299 && !isLogin(r.body)) {
                    Regex("(?is)<input\\b[^>]*>").findAll(r.body).forEach { m ->
                        val tag = m.value
                        val name = attr(tag, "name") ?: attr(tag, "id")
                        val value = attr(tag, "value")
                        if (name != null && value != null) {
                            val k = name.lowercase()
                            if (k.contains("ssid")) ssids.add(name + " = " + value)
                            if (k.contains("wpa") || k.contains("pre_shared") || k.contains("keypass")) keys.add(name + " = " + value)
                        }
                    }
                }
                path + " -> HTTP " + r.code + ", " + r.body.length + " karakter, " + if (isLogin(r.body)) "halaman login" else preview(r.body, 65)
            } catch (e: Exception) { path + " -> " + e.javaClass.simpleName }
        }
        val summary = details.joinToString("\n") + "\n\nSSID: " + (if (ssids.isEmpty()) "belum ditemukan" else ssids.joinToString("; ")) +
            "\nField password: " + (if (keys.isEmpty()) "belum ditemukan / disembunyikan" else keys.joinToString("; "))
        return WifiReadResult(summary, ssids.toList(), keys.toList())
    }

    private fun request(path: String, method: String, data: String?, anonymous: Boolean): HttpResult {
        val c = (URL(base + path).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 7000
            readTimeout = 7000
            instanceFollowRedirects = false
            useCaches = false
            setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 Chrome/131.0 Mobile Safari/537.36")
            setRequestProperty("Connection", "keep-alive")
            setRequestProperty("Referer", base + "/")
            if (anonymous) setRequestProperty("Cookie", "Cookie=body:Language:english:id=-1")
            if (data != null) {
                doOutput = true
                setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
            }
        }
        try {
            if (data != null) c.outputStream.use { it.write(data.toByteArray(StandardCharsets.UTF_8)) }
            val code = c.responseCode
            val stream = if (code >= 400) c.errorStream else c.inputStream
            val body = stream?.use { BufferedReader(InputStreamReader(it, StandardCharsets.UTF_8)).readText() } ?: ""
            val setCookie = c.headerFields.filterKeys { it?.equals("Set-Cookie", true) == true }.values.flatten()
            return HttpResult(code, body, setCookie, c.contentType)
        } finally { c.disconnect() }
    }

    private fun isLogin(s: String) = s.contains("login.cgi", true) || s.contains("name=\"username\"", true) || s.contains("name=\"password\"", true)
    private fun attr(tag: String, key: String): String? = Regex("(?is)\\b" + Regex.escape(key) + "\\s*=\\s*(['\"])(.*?)\\1").find(tag)?.groupValues?.get(2)
    private fun preview(s: String, n: Int = 130) = s.replace(Regex("[\\r\\n\\t]+"), " ").replace(Regex("(?i)(password|passwd|token|sid)\\s*[:=]\\s*[^&\\s<]+"), "$1=***").take(n).ifBlank { "(kosong)" }
    private fun enc(s: String) = URLEncoder.encode(s, "UTF-8")
}