package app.woodwardtunnel.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Icon
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import app.woodwardtunnel.BuildConfig
import app.woodwardtunnel.R
import app.woodwardtunnel.bindings.Core
import app.woodwardtunnel.vpn.ConnectionTest
import app.woodwardtunnel.vpn.EngineLog
import app.woodwardtunnel.vpn.Level
import app.woodwardtunnel.vpn.TestItem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import app.woodwardtunnel.vpn.EngineRuntime
import app.woodwardtunnel.vpn.TunnelState

/** "تنظیمات تخصصی": everything technical lives here, away from the main screen. */
@Composable
fun SettingsScreen(
    onBack: () -> Unit,
    onSubscription: (String) -> Unit,
    onMessage: (Int) -> Unit,
    activeProtocol: String? = null,
) {
    val ctx = LocalContext.current
    var dns by remember { mutableStateOf(Prefs.dnsServers(ctx).joinToString(", ")) }
    var dnsError by remember { mutableStateOf(false) }
    var sub by remember { mutableStateOf("") }
    var report by remember { mutableStateOf<String?>(null) }
    var testRunning by remember { mutableStateOf(false) }
    var testItems by remember { mutableStateOf<List<TestItem>?>(null) }
    var testShown by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    var subError by remember { mutableStateOf(false) }

    Column(
        Modifier.widthIn(max = 640.dp).fillMaxSize().statusBarsPadding().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onBack) {
                // Mirrors automatically in right-to-left layouts.
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                Spacer(Modifier.width(6.dp))
                Text(stringResource(R.string.action_back))
            }
        }
        Text(
            stringResource(R.string.settings_title), style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold, modifier = Modifier.semantics { heading() },
        )
        Text(stringResource(R.string.settings_warning), style = MaterialTheme.typography.bodyMedium)

        HorizontalDivider()
        Text(stringResource(R.string.settings_dns_title), style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            value = dns,
            onValueChange = { dns = it; dnsError = false },
            isError = dnsError,
            singleLine = true,
            textStyle = LocalTextStyle.current.copy(textDirection = TextDirection.Ltr),
            supportingText = {
                Text(stringResource(if (dnsError) R.string.settings_dns_invalid else R.string.settings_dns_hint))
            },
            modifier = Modifier.fillMaxWidth(),
        )
        Button(onClick = {
            val parsed = Prefs.parseDns(dns)
            if (parsed == null) dnsError = true else {
                Prefs.setDnsServers(ctx, parsed)
                dns = parsed.joinToString(", ")
                onMessage(R.string.settings_saved)
            }
        }) { Text(stringResource(R.string.action_save)) }

        HorizontalDivider()
        var verify by remember { mutableStateOf(Prefs.verifyInternet(ctx)) }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(stringResource(R.string.settings_verify_title), style = MaterialTheme.typography.titleMedium)
                Text(stringResource(R.string.settings_verify_body), style = MaterialTheme.typography.bodySmall)
            }
            Switch(checked = verify, onCheckedChange = { verify = it; Prefs.setVerifyInternet(ctx, it) })
        }

        HorizontalDivider()
        Text(stringResource(R.string.settings_subscription_title), style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            value = sub,
            onValueChange = { sub = it; subError = false },
            isError = subError,
            singleLine = true,
            textStyle = LocalTextStyle.current.copy(textDirection = TextDirection.Ltr),
            label = { Text(stringResource(R.string.settings_subscription_hint)) },
            supportingText = { if (subError) Text(stringResource(R.string.settings_subscription_invalid)) },
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedButton(onClick = {
            val u = sub.trim()
            if (u.startsWith("https://", ignoreCase = true) && u.length > 10) {
                onSubscription(u)
                sub = ""
            } else subError = true
        }) { Text(stringResource(R.string.subscription_download)) }

        HorizontalDivider()
        Text(stringResource(R.string.settings_killswitch_title), style = MaterialTheme.typography.titleMedium)
        Text(stringResource(R.string.settings_killswitch_body), style = MaterialTheme.typography.bodyMedium)
        OutlinedButton(onClick = { if (!openVpnSettings(ctx)) onMessage(R.string.settings_killswitch_failed) }) {
            Text(stringResource(R.string.settings_killswitch_open))
        }

        if (Build.VERSION.SDK_INT >= 33) {
            HorizontalDivider()
            Text(stringResource(R.string.settings_language_title), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(R.string.settings_language_body), style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = {
                runCatching {
                    ctx.startActivity(
                        Intent(Settings.ACTION_APP_LOCALE_SETTINGS, android.net.Uri.fromParts("package", ctx.packageName, null))
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                    )
                }
            }) { Text(stringResource(R.string.settings_language_open)) }
        }

        HorizontalDivider()
        Text(stringResource(R.string.settings_details_title), style = MaterialTheme.typography.titleMedium)
        Text(
            TunnelState.lastTechnical ?: stringResource(R.string.settings_details_none),
            style = MaterialTheme.typography.bodySmall,
        )

        HorizontalDivider()
        Text(stringResource(R.string.settings_test_title), style = MaterialTheme.typography.titleMedium)
        Text(stringResource(R.string.settings_test_body), style = MaterialTheme.typography.bodySmall)
        OutlinedButton(enabled = !testRunning, onClick = {
            testRunning = true
            testShown = true
            testItems = null
            scope.launch {
                testItems = withContext(Dispatchers.IO) { ConnectionTest.run(ctx) }
                testRunning = false
            }
        }) { Text(stringResource(R.string.settings_test_button)) }

        HorizontalDivider()
        Text(stringResource(R.string.settings_diag_title), style = MaterialTheme.typography.titleMedium)
        Text(stringResource(R.string.settings_diag_body), style = MaterialTheme.typography.bodySmall)
        OutlinedButton(onClick = {
            scope.launch {
                report = withContext(Dispatchers.IO) {
                    try {
                        Core.init(ctx)
                        Core.get().diagnosticReport(EngineLog.snapshot()) +
                            "\n\nconnection health:\n" + ConnectionTest.reportLines().joinToString("\n") { "  $it" } + "\n"
                    } catch (e: Exception) {
                        ""
                    }
                }
            }
        }) { Text(stringResource(R.string.settings_diag_button)) }

        HorizontalDivider()
        Text(stringResource(R.string.settings_about_title), style = MaterialTheme.typography.titleMedium)
        Text(
            stringResource(R.string.settings_about_body, BuildConfig.VERSION_NAME, EngineRuntime.version()),
            style = MaterialTheme.typography.bodySmall,
        )
        Spacer(Modifier.height(32.dp))
    }

    if (testShown) {
        AlertDialog(
            onDismissRequest = { if (!testRunning) testShown = false },
            title = { Text(stringResource(R.string.settings_test_title)) },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    when {
                        testRunning -> Row(verticalAlignment = Alignment.CenterVertically) {
                            CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                            Spacer(Modifier.width(12.dp))
                            Text(stringResource(R.string.ct_running))
                        }
                        testItems == null -> Text(stringResource(R.string.ct_need_connect))
                        else -> {
                            testItems!!.forEach { item ->
                                Column {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Text(
                                            when (item.level) { Level.OK -> "✓"; Level.WARN -> "!"; Level.FAIL -> "✗"; Level.INFO -> "i" },
                                            color = when (item.level) {
                                                Level.OK -> StateColors.connected
                                                Level.WARN -> StateColors.connecting
                                                Level.FAIL -> StateColors.error
                                                Level.INFO -> StateColors.idle
                                            },
                                            fontWeight = FontWeight.Bold,
                                        )
                                        Spacer(Modifier.width(8.dp))
                                        Text(stringResource(item.title), fontWeight = FontWeight.Medium)
                                    }
                                    Text(stringResource(item.note), style = MaterialTheme.typography.bodySmall)
                                }
                            }
                            if (activeProtocol != null) {
                                Text(stringResource(R.string.ct_protocol, activeProtocol), style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                }
            },
            confirmButton = { TextButton(enabled = !testRunning, onClick = { testShown = false }) { Text(stringResource(R.string.action_close)) } },
        )
    }

    report?.let { text ->
        AlertDialog(
            onDismissRequest = { report = null },
            title = { Text(stringResource(R.string.settings_diag_title)) },
            text = {
                Column {
                    Text(stringResource(R.string.settings_diag_note), style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text.ifBlank { stringResource(R.string.err_storage) },
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        style = LocalTextStyle.current.copy(textDirection = TextDirection.Ltr),
                        modifier = Modifier.weight(1f, fill = false).verticalScroll(rememberScrollState()),
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    val clip = ClipData.newPlainText("diagnostic report", text)
                    // Android 13+: hide the copied text from the clipboard preview overlay.
                    clip.description.extras = android.os.PersistableBundle().apply {
                        putBoolean("android.content.extra.IS_SENSITIVE", true)
                    }
                    cm.setPrimaryClip(clip)
                    onMessage(R.string.settings_diag_copied)
                }) { Text(stringResource(R.string.settings_diag_copy)) }
            },
            dismissButton = { TextButton(onClick = { report = null }) { Text(stringResource(R.string.action_close)) } },
        )
    }
}

private fun openVpnSettings(ctx: Context): Boolean = try {
    ctx.startActivity(Intent(Settings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    true
} catch (e: Exception) {
    false
}
