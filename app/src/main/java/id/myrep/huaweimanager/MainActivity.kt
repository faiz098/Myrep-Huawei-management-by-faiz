package id.myrep.huaweimanager
import android.app.Activity
import android.os.Bundle
import android.content.Context
import android.content.ClipData
import android.content.ClipboardManager
import android.net.wifi.WifiManager
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.View
import android.widget.*
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.util.concurrent.Executors

class MainActivity : Activity() {
 private val worker=Executors.newSingleThreadExecutor()
 private lateinit var ip:EditText
 private lateinit var user:EditText
 private lateinit var pass:EditText
 private lateinit var status:TextView
 private lateinit var login:Button
 private lateinit var progress:ProgressBar
 private lateinit var wifiPanel:LinearLayout
 private lateinit var dashboardPanel:LinearLayout
 private val purple=Color.rgb(91,45,170)
 private val ink=Color.rgb(31,35,48)
 private val muted=Color.rgb(111,117,132)
 override fun onCreate(savedInstanceState:Bundle?) {
  super.onCreate(savedInstanceState)
  window.statusBarColor=Color.rgb(77,36,145); window.navigationBarColor=Color.WHITE
  window.decorView.systemUiVisibility=View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR
  val root=LinearLayout(this).apply{orientation=1;setBackgroundColor(Color.rgb(246,247,251))}
  val scroll=ScrollView(this).apply{isFillViewport=true}
  val page=LinearLayout(this).apply{orientation=1;setPadding(dp(20),dp(18),dp(20),dp(28))}
  scroll.addView(page);root.addView(scroll,LinearLayout.LayoutParams(-1,0,1f))
  val hero=LinearLayout(this).apply{orientation=1;setPadding(dp(20),dp(22),dp(20),dp(22));background=shape(Color.rgb(77,36,145),22)}
  hero.addView(label("MYREP",13,Color.rgb(225,210,255),true))
  hero.addView(label("Huawei Management",25,Color.WHITE,true))
  hero.addView(label("Kelola router dari jaringan WiFi rumah.",13,Color.WHITE))
  page.addView(hero,spacer(18))
  dashboardPanel=card().apply{visibility=View.GONE}
  dashboardPanel.addView(label("DASHBOARD ROUTER",15,ink,true),spacer(8))
  page.addView(dashboardPanel,spacer(16))
  page.addView(label("Koneksi router",17,ink,true),spacer(10))
  val net=card();net.addView(fieldLabel("Alamat IP router"))
  ip=field("Contoh: 192.168.100.1").apply{setText(gateway())};net.addView(ip,spacer(10))
  val detect=button("Deteksi gateway otomatis",false);net.addView(detect)
  detect.setOnClickListener{val g=gateway();if(g.isBlank())show("Gateway tidak ditemukan. Sambungkan HP ke WiFi router.",false) else {ip.setText(g);show("Gateway ditemukan: $g",true)}}
  page.addView(net,spacer(16))
  page.addView(label("Login router",17,ink,true),spacer(10))
  val acc=card();acc.addView(fieldLabel("Username"));user=field("Username router");acc.addView(user,spacer(12))
  acc.addView(fieldLabel("Password"));pass=field("Password router").apply{inputType=129};acc.addView(pass,spacer(8))
  acc.addView(label("Gunakan akun yang diizinkan pemilik router. Data login diproses di HP.",11,muted))
  page.addView(acc,spacer(16))
  val row=LinearLayout(this).apply{orientation=0}
  val test=button("Tes koneksi",false);login=button("Login Huawei",true)
  row.addView(test,LinearLayout.LayoutParams(0,dp(50),1f).apply{rightMargin=dp(8)})
  row.addView(login,LinearLayout.LayoutParams(0,dp(50),1f).apply{leftMargin=dp(8)})
  page.addView(row,spacer(14));test.setOnClickListener{testConnection()};login.setOnClickListener{loginRouter()}
  val box=card();val head=LinearLayout(this).apply{gravity=Gravity.CENTER_VERTICAL}
  head.addView(label("STATUS & DIAGNOSTIK",11,muted,true),LinearLayout.LayoutParams(0,-2,1f))
  val copy=button("Salin",false).apply{textSize=11f;minimumWidth=dp(64);minimumHeight=dp(36);setPadding(dp(8),0,dp(8),0)}
  head.addView(copy,LinearLayout.LayoutParams(-2,dp(36)).apply{rightMargin=dp(8)})
  copy.setOnClickListener{
   val text=status.text?.toString().orEmpty()
   if(text.isBlank()){Toast.makeText(this,"Belum ada diagnostik untuk disalin.",Toast.LENGTH_SHORT).show()}
   else {
    val clipboard=getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    clipboard.setPrimaryClip(ClipData.newPlainText("Status & Diagnostik MYREP",text))
    Toast.makeText(this,"Status & diagnostik berhasil disalin.",Toast.LENGTH_SHORT).show()
   }
  }
  progress=ProgressBar(this).apply{visibility=View.GONE};head.addView(progress,LinearLayout.LayoutParams(dp(22),dp(22)))
  box.addView(head);status=label("Belum ada pengujian. Masukkan akun router lalu tekan Login Huawei.",13,ink).apply{setPadding(0,dp(12),0,0)}
  box.addView(status);page.addView(box,spacer(16))
  wifiPanel=card().apply{visibility=View.GONE}
  page.addView(wifiPanel,spacer(16))
  page.addView(label("Catatan kompatibilitas",14,ink,true),spacer(6))
  page.addView(label("Firmware Huawei dari ISP dapat memakai metode autentikasi berbeda. Diagnostik akan menunjukkan tahap yang gagal. Aplikasi saat ini hanya membaca data, belum mengubah konfigurasi router.",12,muted))
  setContentView(root)
 }
 private fun dp(v:Int)=(v*resources.displayMetrics.density).toInt()
 private fun shape(c:Int,r:Int)=GradientDrawable().apply{setColor(c);cornerRadius=dp(r).toFloat()}
 private fun spacer(b:Int)=LinearLayout.LayoutParams(-1,-2).apply{bottomMargin=dp(b)}
 private fun card()=LinearLayout(this).apply{orientation=1;setPadding(dp(16),dp(16),dp(16),dp(16));background=GradientDrawable().apply{setColor(Color.WHITE);cornerRadius=dp(18).toFloat();setStroke(dp(1),Color.rgb(232,234,241))}}
 private fun label(s:String,n:Int,c:Int,b:Boolean=false)=TextView(this).apply{text=s;textSize=n.toFloat();setTextColor(c);if(b)typeface=Typeface.create("sans-serif-medium",0);setLineSpacing(dp(2).toFloat(),1f)}
 private fun fieldLabel(s:String)=label(s,12,muted,true).apply{setPadding(0,0,0,dp(6))}
 private fun field(h:String)=EditText(this).apply{hint=h;textSize=14f;setTextColor(ink);setSingleLine(true);setPadding(dp(13),dp(12),dp(13),dp(12));background=GradientDrawable().apply{setColor(Color.rgb(248,249,252));cornerRadius=dp(12).toFloat();setStroke(dp(1),Color.rgb(226,228,236))};layoutParams=LinearLayout.LayoutParams(-1,dp(48))}
 private fun button(s:String,primary:Boolean)=Button(this).apply{text=s;textSize=13f;isAllCaps=false;setTextColor(if(primary)Color.WHITE else purple);background=shape(if(primary)purple else Color.rgb(243,239,252),13)}
 @Suppress("DEPRECATION") private fun gateway():String=try{val w=getSystemService(Context.WIFI_SERVICE) as WifiManager;val v=w.dhcpInfo.gateway;if(v==0)"" else listOf(0,8,16,24).joinToString("."){((v shr it) and 255).toString()}}catch(_:Exception){""}
 private fun show(s:String,ok:Boolean){status.text=s;status.setTextColor(if(ok)Color.rgb(27,117,76) else ink)}
 private fun busy(s:String){login.isEnabled=false;progress.visibility=View.VISIBLE;status.text=s}

 private fun renderDashboard(routerIp:String, username:String, wifi:HuaweiLegacyClient.WifiReadResult?) {
  dashboardPanel.removeAllViews()
  dashboardPanel.visibility=View.VISIBLE
  dashboardPanel.addView(label("DASHBOARD ROUTER",15,ink,true),spacer(8))
  val details=listOf(
   "Status koneksi" to "Login berhasil",
   "IP router" to routerIp,
   "Username" to username,
   "Model perangkat" to "Belum terdeteksi dari firmware",
   "Status internet" to "Belum diverifikasi"
  )
  details.forEach { (title,value) ->
   val line=LinearLayout(this).apply{orientation=0;gravity=Gravity.CENTER_VERTICAL}
   line.addView(label(title,12,muted),LinearLayout.LayoutParams(0,-2,1f))
   line.addView(label(value,13,ink,true))
   dashboardPanel.addView(line,spacer(7))
  }
  val ssids=wifi?.ssids.orEmpty()
  dashboardPanel.addView(label("WiFi 2.4 GHz",12,purple,true),spacer(3))
  dashboardPanel.addView(label(ssids.firstOrNull{it.startsWith("2.4 GHz:")}?.substringAfter(":")?.trim() ?: "Belum terbaca",14,ink,true),spacer(7))
  dashboardPanel.addView(label("WiFi 5 GHz",12,purple,true),spacer(3))
  dashboardPanel.addView(label(ssids.firstOrNull{it.startsWith("5 GHz:")}?.substringAfter(":")?.trim() ?: "Belum terbaca",14,ink,true))
 }
 private fun renderWifiCandidates(items:List<String>,diagnostics:List<String>){
  wifiPanel.removeAllViews()
  wifiPanel.visibility=View.VISIBLE
  wifiPanel.addView(label("PENGELOLAAN WI-FI",15,ink,true),spacer(8))
  val bands=listOf("2.4 GHz","5 GHz")
  bands.forEach { band ->
   val match=items.firstOrNull{it.startsWith("$band:")}
   val ssid=match?.substringAfter(":")?.trim().orEmpty()
   val row=LinearLayout(this).apply{orientation=1;setPadding(dp(14),dp(13),dp(14),dp(13));background=shape(Color.rgb(247,245,252),14)}
   row.addView(label(band,14,purple,true),spacer(5))
   row.addView(label(if(ssid.isBlank()) "SSID belum ditemukan" else ssid,17,ink,true),spacer(8))
   row.addView(label("Status Wi-Fi: belum diverifikasi",12,muted))
   row.addView(label("Channel / bandwidth: belum diverifikasi",12,muted))
   row.addView(label("Mode / security: belum diverifikasi",12,muted))
   row.addView(label("Password: tidak dibaca demi keamanan; kemampuan firmware belum diverifikasi",12,muted),spacer(8))
   val actions=LinearLayout(this).apply{orientation=0}
   listOf("Edit SSID","Edit Password","Simpan").forEach { title ->
    val b=button(title,false).apply{isEnabled=false;alpha=0.48f;textSize=10f}
    actions.addView(b,LinearLayout.LayoutParams(0,dp(42),1f).apply{if(title!="Edit SSID")leftMargin=dp(5)})
   }
   row.addView(actions)
   wifiPanel.addView(row,spacer(10))
  }
  wifiPanel.addView(label("DIAGNOSTIK YANG PERLU DIKIRIM",14,ink,true),spacer(6))
  wifiPanel.addView(label("Setiap fungsi dipisah agar bisa disalin satu per satu. Bagian panjang otomatis dibagi menjadi potongan maksimal 3.000 karakter. Kirim sesuai urutan nama fungsi dan nomor potongan.",11,muted),spacer(8))
  diagnostics.forEachIndexed { index, section ->
   val title=section.lineSequence().firstOrNull()?.take(110) ?: "Bagian diagnostik $index"
   val body=section
   val chunks=body.chunked(3000)
   val group=LinearLayout(this).apply{orientation=1;setPadding(dp(10),dp(10),dp(10),dp(10));background=shape(Color.rgb(247,245,252),12)}
   group.addView(label(title,11,purple,true),spacer(5))
   group.addView(label("Total ${body.length} karakter • ${chunks.size} potongan",10,muted),spacer(5))
   chunks.forEachIndexed { part, chunk ->
    val b=button("Salin ${part+1}/${chunks.size}",false).apply{textSize=11f}
    b.setOnClickListener{copyDiagnostic(chunk,"Bagian ${index+1}, potongan ${part+1}")}
    group.addView(b,spacer(5))
   }
   wifiPanel.addView(group,spacer(8))
  }
  if(diagnostics.isEmpty()) wifiPanel.addView(label("Belum ada fungsi yang berhasil diekstrak. Periksa status diagnostik di atas.",11,muted),spacer(8))
  wifiPanel.addView(label("Tombol perubahan belum diaktifkan. Firmware belum mengungkap dan memverifikasi endpoint serta parameter simpan. Aplikasi tidak mengirim perubahan ke router.",11,muted))
 }
 private fun copyDiagnostic(value:String,description:String){
  val clipboard=getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
  clipboard.setPrimaryClip(ClipData.newPlainText(description,value))
  Toast.makeText(this,"$description disalin. Tempelkan ke chat.",Toast.LENGTH_SHORT).show()
 }
 private fun host()=ip.text.toString().trim().removePrefix("http://").removePrefix("https://").trimEnd('/')
 private fun valid(s:String)=s.isNotBlank()&&!s.contains('/')&&!s.contains(' ')&&!s.contains(':')
 private fun testConnection(){val h=host();if(!valid(h)){show("Masukkan IP router yang valid.",false);return};busy("Menguji koneksi...")
  worker.execute{val out=try{val a=InetAddress.getByName(h);if(!a.isSiteLocalAddress&&!a.isLoopbackAddress)error("Alamat bukan jaringan lokal");val c=URL("http://$h/").openConnection() as HttpURLConnection;c.connectTimeout=5000;c.readTimeout=5000;val code=c.responseCode;c.disconnect();"HTTP $code. Jalur jaringan tersedia, login belum terverifikasi."}catch(e:Exception){"Koneksi gagal: ${e.message}"};runOnUiThread{progress.visibility=View.GONE;login.isEnabled=true;show(out,out.startsWith("HTTP"))}}
 }
 private fun loginRouter(){val h=host();val u=user.text.toString().trim();val p=pass.text.toString();if(!valid(h)||u.isBlank()||p.isBlank()){show("Isi IP, username, dan password router.",false);return};busy("Memeriksa autentikasi Huawei...")
  worker.execute{
   val client=HuaweiLegacyClient(h)
   val auth=client.login(u,p)
   val wifi=if(auth.success) client.readWifiSettings() else null
   runOnUiThread{
    progress.visibility=View.GONE
    login.isEnabled=true
    show(auth.message + if(wifi!=null) "\n\n" + wifi.summary else "",auth.success)
    if(auth.success) renderDashboard(h,u,wifi)
    if(wifi!=null) renderWifiCandidates(wifi.ssids,wifi.diagnosticSections)
   }
  }
 }
 override fun onDestroy(){worker.shutdownNow();super.onDestroy()}
}