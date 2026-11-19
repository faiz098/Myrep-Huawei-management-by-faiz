package id.myrep.huaweimanager

import android.util.Base64
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

class HuaweiLegacyClient(hostInput: String) {
    private val host = hostInput.trim().removePrefix("http://").removePrefix("https://").trimEnd('/')
    private val base = "http://" + host
    // Cookie storage is scoped to this router client. No JVM-global CookieHandler.
    private val cookieHeaders = linkedMapOf<String, String>()
    private var sessionToken: String? = null

    data class LoginResult(val success: Boolean, val message: String)
    data class WifiReadResult(val summary: String, val ssids: List<String>, val passwordFields: List<String>)
    private data class HttpResult(val code: Int, val body: String, val setCookie: List<String>, val type: String?)

    fun login(username: String, password: String): LoginResult {
        if (host.isBlank() || username.isBlank() || password.isBlank()) return LoginResult(false, "IP, username, dan password wajib diisi.")
        return try {
            cookieHeaders.clear()
            val tokenReply = request("/asp/GetRandCount.asp", "POST", null, true)
            val token = tokenReply.body.removePrefix("\uFEFF").trim()
            if (token.isBlank() || token.length > 256 || token.contains('<') || token.contains(' ')) {
                return LoginResult(false, "GAGAL PADA TOKEN LOGIN\nHTTP: " + tokenReply.code + "\nContent-Type: " + (tokenReply.type ?: "tidak ada") + "\nRespons: " + preview(tokenReply.body))
            }
            val encoded = Base64.encodeToString(password.toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP)
            val form = listOf("UserName" to username, "PassWord" to encoded, "Language" to "english", "x.X_HW_Token" to token)
                .joinToString("&") { (k, v) -> enc(k) + "=" + enc(v) }
            val reply = request("/login.cgi", "POST", form, true)
            val cookieNames = cookieHeaders.keys.joinToString().ifBlank { "tidak ada" }
            val cookieOk = cookieHeaders.any { (name, value) ->
                (name.equals("Cookie", true) && value.contains("sid=", true) && !value.contains("id=-1", true)) ||
                (name.equals("sid", true) && value.isNotBlank())
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
        val candidates = listOf(
            "/html/amp/wlanbasic/WlanBasic.asp",
            "/html/bbsp/wlan/wlanbasic.asp",
            "/html/amp/wlanbasic/wlan.asp",
            "/html/bbsp/wlan/wlan.asp"
        )
        val attempts = mutableListOf<String>()
        var pagePath: String? = null
        var page = ""
        for (path in candidates) {
            try {
                val r = request(path, "GET", null, false)
                attempts.add("$path -> HTTP ${r.code}, ${r.body.length} karakter")
                if (r.code in 200..299 && !isLogin(r.body) && r.body.isNotBlank()) {
                    pagePath = path
                    page = r.body
                    break
                }
            } catch (e: Exception) {
                attempts.add("$path -> ${e.javaClass.simpleName}")
            }
        }
        if (pagePath == null) {
            return WifiReadResult(
                "Halaman WLAN tidak berhasil dibaca.\n" + attempts.joinToString("\n"),
                emptyList(),
                emptyList()
            )
        }

        val ssids = parseWlanWifiArray(page)
        val inventory = linkedSetOf<String>()
        val scripts = Regex("(?is)<script\\b[^>]*src\\s*=\\s*(['\\\"])(.*?)\\1[^>]*>")
            .findAll(page).mapNotNull { it.groupValues[2].trim().takeIf(String::isNotBlank) }
            .distinct().toList()
        val inlineScript = Regex("(?is)<script\\b(?![^>]*src\\s*=)[^>]*>(.*?)</script>")
            .findAll(page).joinToString("\n") { it.groupValues[1] }

        fun auditSource(label: String, source: String) {
            val patterns = listOf(
                Regex("(?is).{0,180}function\\s+(?:stWlanWifi|[^\\s(]*(?:wlan|ssid|wifi|psk|pwd|save|submit|init)[^\\s(]*)\\s*\\([^)]*\\).{0,700}"),
                Regex("(?is).{0,180}(?:XMLHttpRequest|\\$\\.ajax|\\$\\.post|\\$\\.get|ajax\\s*\\().{0,500}"),
                Regex("(?is).{0,180}(?:\\.\\./|/)[^'\\\"\\s<>]*(?:wlan|wifi|ajax|asp|cgi)[^'\\\"\\s<>]*.{0,100}")
            )
            patterns.forEach { pattern ->
                pattern.findAll(source).take(16).forEach { match ->
                    val safe = match.value
                        .replace(Regex("(?i)(password|passwd|wpapsk|preSharedKey|wlKeys[1-4])\\s*([=:]\\s*['\\\"]?)[^'\\\";,}\\s<]+"), "$1$2***")
                        .replace(Regex("[\\r\\n\\t]+"), " ")
                        .take(520)
                    inventory.add("$label: $safe")
                }
            }
        }

        auditSource("INLINE", inlineScript)
        val scriptResults = mutableListOf<String>()
        scripts.forEach { src ->
            try {
                val resolved = when {
                    src.startsWith("http://", true) || src.startsWith("https://", true) -> src
                    src.startsWith("/") -> base + src
                    else -> base + pagePath.substringBeforeLast('/') + "/" + src
                }
                // Only request scripts from this router. Never forward credentials to another host.
                if (!resolved.startsWith(base + "/", true)) {
                    scriptResults.add("$src -> dilewati (host eksternal)")
                } else {
                    val relative = resolved.removePrefix(base)
                    val r = request(relative, "GET", null, false)
                    scriptResults.add("$src -> HTTP ${r.code}, ${r.body.length} karakter")
                    if (r.code in 200..299) auditSource(src.substringAfterLast('/'), r.body)
                }
            } catch (e: Exception) {
                scriptResults.add("$src -> ${e.javaClass.simpleName}")
            }
        }

        val fullFunctionAudit = mutableListOf<String>()
        val endpointAudit = linkedSetOf<String>()
        val functionNames = listOf(
            "SubmitForm", "addParameter1", "addParameter2", "addParameter3",
            "webSubmitForm", "isBsdPskPwdChange", "CheckPskLenValid",
            "SsidEnable", "ShowSsidEnable", "initWlanBasic", "initWlanCap",
            "FirstRecordFor5G", "IsSetSsid5G", "isSetTriBand"
        )
        fun collectDeepAudit(label: String, source: String) {
            functionNames.forEach { name ->
                extractJsFunction(source, name)?.let { extracted ->
                    fullFunctionAudit.add("===== $label :: $name (${extracted.length} karakter) =====\\n" + redactJsSecrets(extracted).take(8000) + if (extracted.length > 8000) "\\n[Dipangkas pada 8.000 karakter; fungsi lengkap tersedia di source firmware]" else "")
                }
            }
            Regex("""(?is)(?:set\.cgi|add\.cgi|del\.cgi|[A-Za-z0-9_./-]+\.asp(?:\?[^'"\s<>]*)?)[^'"\s<>]{0,300}""")
                .findAll(source).take(100).forEach { endpointAudit.add(it.value) }
            Regex("""(?is)(?:url\s*:\s*['"][^'"]+|setAction\s*\(\s*['"][^'"]+|RequestFile=[^'"\s<>]+)""")
                .findAll(source).take(100).forEach { endpointAudit.add(it.value) }
        }
        collectDeepAudit("INLINE", inlineScript)
        scripts.forEach { src ->
            try {
                val resolved = when {
                    src.startsWith("http://", true) || src.startsWith("https://", true) -> src
                    src.startsWith("/") -> base + src
                    else -> base + pagePath.substringBeforeLast('/') + "/" + src
                }
                if (resolved.startsWith(base + "/", true)) {
                    val r = request(resolved.removePrefix(base), "GET", null, false)
                    if (r.code in 200..299) collectDeepAudit(src.substringAfterLast('/'), r.body)
                }
            } catch (_: Exception) { }
        }
        val ssidLabels = ssids.joinToString("; ").ifBlank { "belum ditemukan" }
        val summary = buildString {
            append("HALAMAN WLAN: $pagePath (HTTP 200)\n")
            append("Pemetaan profil WlanWifiArr (metadata, bukan runtime): $ssidLabels\n")
            append("File JavaScript eksternal:\n")
            append(scriptResults.take(30).joinToString("\n").ifBlank { "Tidak ada script eksternal terdeteksi." })
            append("\n\nFUNGSI JAVASCRIPT LENGKAP (ekstraksi statis, tidak dieksekusi):\n")
            append(fullFunctionAudit.distinct().joinToString("\n\n").ifBlank { "Fungsi target belum ditemukan." })
            append("\n\nENDPOINT / URL TERDETEKSI (bukan bukti request runtime):\n")
            append(endpointAudit.take(100).joinToString("\n").ifBlank { "Belum ditemukan." })
            append("\n\nPETUNJUK FUNGSI / REQUEST (hasil audit statis):\n")
            append(inventory.take(45).joinToString("\n").ifBlank { "Belum ditemukan pola fungsi/request yang cocok." })
            append("\n\nBATASAN: audit hanya membaca source HTML/JavaScript. Tidak menjalankan fungsi, tidak mengirim POST, dan tidak mengubah konfigurasi router. WlanWifiArr tetap dianggap metadata. Nilai runtime radio, channel, bandwidth, mode, keamanan, dan password belum terverifikasi.")
            append("\n\nJalur yang diperiksa:\n")
            append(attempts.joinToString("\n"))
        }
        return WifiReadResult(summary, ssids, emptyList())
    }

    // Extract a complete named JavaScript function without executing it.
    // Tracks strings, comments, and nested braces.
    private fun extractJsFunction(source: String, name: String): String? {
        val declaration = Regex("""\bfunction\s+""" + Regex.escape(name) + """\s*\(""")
        val match = declaration.find(source) ?: return null
        val openBrace = source.indexOf('{', match.range.last + 1)
        if (openBrace < 0) return null
        var depth = 0
        var quote: Char? = null
        var escaped = false
        var lineComment = false
        var blockComment = false
        var template = false
        var i = openBrace
        while (i < source.length) {
            val c = source[i]
            val next = if (i + 1 < source.length) source[i + 1] else '\u0000'
            when {
                lineComment -> if (c == '\n') lineComment = false
                blockComment -> if (c == '*' && next == '/') { blockComment = false; i++ }
                quote != null || template -> {
                    if (escaped) escaped = false
                    else if (c == '\\') escaped = true
                    else if (template && c.code == 96) template = false
                    else if (!template && c == quote) quote = null
                }
                c == '/' && next == '/' -> { lineComment = true; i++ }
                c == '/' && next == '*' -> { blockComment = true; i++ }
                c == '\'' || c == '"' -> quote = c
                c.code == 96 -> template = true
                c == '{' -> depth++
                c == '}' -> {
                    depth--
                    if (depth == 0) return source.substring(match.range.first, i + 1)
                }
            }
            i++
        }
        return null
    }

    private fun redactJsSecrets(code: String): String {
        var safe = code
        safe = safe.replace(
            Regex("""(?is)((?:password|passwd|wpapsk|preSharedKey|wlKeys[1-4]|onttoken|token|sid)\s*[:=]\s*)(['"])[^'"]*\2"""),
            "$1\"***\""
        )
        safe = safe.replace(
            Regex("""(?is)((?:password|passwd|wpapsk|preSharedKey|wlKeys[1-4]|onttoken|token|sid)\s*[:=]\s*)[^,;\s}]+"""),
            "$1***"
        )
        return safe.take(50000)
    }

    private fun parseWlanWifiArray(html: String): List<String> {
        if (html.isBlank()) return emptyList()
        val body = Regex("(?is)WlanWifiArr\\s*=\\s*new\\s+Array\\((.*?)\\);")
            .find(html)?.groupValues?.get(1) ?: return emptyList()
        val constructors = Regex("(?is)new\\s+stWlanWifi\\((.*?)\\)")
        val quoted = Regex("""("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')""")
        val result = linkedSetOf<String>()
        constructors.findAll(body).forEach { match ->
            val args = quoted.findAll(match.groupValues[1]).map { token ->
                token.value.substring(1, token.value.length - 1)
                    .replace(Regex("""\\x([0-9a-fA-F]{2})""")) { m ->
                        m.groupValues[1].toInt(16).toChar().toString()
                    }
                    .replace("\\\\", "\\")
            }.toList()
            if (args.size >= 5) {
                val path = args[0]
                val ssid = args[3].trim()
                val band = when {
                    path.contains("WLANConfiguration.1") -> "2.4 GHz"
                    path.contains("WLANConfiguration.5") -> "5 GHz"
                    else -> "WLAN"
                }
                if (ssid.isNotBlank() && !ssid.equals("undefined", true) && !ssid.equals("null", true)) {
                    result.add("$band: $ssid")
                }
            }
        }
        return result.toList()
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
            if (anonymous || cookieHeaders.isNotEmpty()) {
                val outgoing = cookieHeaders.toMutableMap()
                if (anonymous && !outgoing.containsKey("Cookie")) {
                    outgoing["Cookie"] = "body:Language:english:id=-1"
                }
                setRequestProperty("Cookie", outgoing.entries.joinToString("; ") { "${it.key}=${it.value}" })
            }
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
            setCookie.forEach { header ->
                val pair = header.substringBefore(';').split("=", limit = 2)
                if (pair.size == 2 && pair[0].isNotBlank()) cookieHeaders[pair[0]] = pair[1]
            }
            return HttpResult(code, body, setCookie, c.contentType)
        } finally { c.disconnect() }
    }

    private fun isLogin(s: String) = s.contains("login.cgi", true) || s.contains("name=\"username\"", true) || s.contains("name=\"password\"", true)
    private fun attr(tag: String, key: String): String? = Regex("(?is)\\b" + Regex.escape(key) + "\\s*=\\s*(['\"])(.*?)\\1").find(tag)?.groupValues?.get(2)
    private fun preview(s: String, n: Int = 130) = s.replace(Regex("[\\r\\n\\t]+"), " ").replace(Regex("(?i)(password|passwd|token|sid)\\s*[:=]\\s*[^&\\s<]+"), "$1=***").take(n).ifBlank { "(kosong)" }
    private fun enc(s: String) = URLEncoder.encode(s, "UTF-8")
}