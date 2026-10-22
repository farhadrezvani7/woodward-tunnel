package app.woodwardtunnel.ui

import android.content.Context
import android.content.Intent
import android.provider.Settings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import app.woodwardtunnel.BuildConfig
import app.woodwardtunnel.R
import app.woodwardtunnel.vpn.EngineRuntime
import app.woodwardtunnel.vpn.TunnelState

/** "تنظیمات تخصصی": everything technical lives here, away from the main screen. */
@Composable
fun SettingsScreen(
    onBack: () -> Unit,
    onSubscription: (String) -> Unit,
    onMessage: (Int) -> Unit,
) {
    val ctx = LocalContext.current
    var dns by remember { mutableStateOf(Prefs.dnsServers(ctx).joinToString(", ")) }
    var dnsError by remember { mutableStateOf(false) }
    var sub by remember { mutableStateOf("") }
    var subError by remember { mutableStateOf(false) }

    Column(
        Modifier.fillMaxSize().statusBarsPadding().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onBack) { Text("‹ " + stringResource(R.string.action_back)) }
        }
        Text(stringResource(R.string.settings_title), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text(stringResource(R.string.settings_warning), style = MaterialTheme.typography.bodyMedium)

        HorizontalDivider()
        Text(stringResource(R.string.settings_dns_title), style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            value = dns,
            onValueChange = { dns = it; dnsError = false },
            isError = dnsError,
            singleLine = true,
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
        Text(stringResource(R.string.settings_subscription_title), style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            value = sub,
            onValueChange = { sub = it; subError = false },
            isError = subError,
            singleLine = true,
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

        HorizontalDivider()
        Text(stringResource(R.string.settings_details_title), style = MaterialTheme.typography.titleMedium)
        Text(
            TunnelState.lastTechnical ?: stringResource(R.string.settings_details_none),
            style = MaterialTheme.typography.bodySmall,
        )

        HorizontalDivider()
        Text(stringResource(R.string.settings_about_title), style = MaterialTheme.typography.titleMedium)
        Text(
            stringResource(R.string.settings_about_body, BuildConfig.VERSION_NAME, EngineRuntime.version()),
            style = MaterialTheme.typography.bodySmall,
        )
        Spacer(Modifier.height(32.dp))
    }
}

private fun openVpnSettings(ctx: Context): Boolean = try {
    ctx.startActivity(Intent(Settings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    true
} catch (e: Exception) {
    false
}
