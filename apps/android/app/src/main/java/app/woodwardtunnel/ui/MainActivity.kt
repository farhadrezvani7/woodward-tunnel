package app.woodwardtunnel.ui

import android.Manifest
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import app.woodwardtunnel.BuildConfig
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.launch
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.material3.MaterialTheme
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.woodwardtunnel.R
import app.woodwardtunnel.vpn.TunnelState
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import uniffi.wtcore.FfiProfile

class MainActivity : ComponentActivity() {
    private val vm: MainViewModel by viewModels()

    private var afterNotificationPermission: (() -> Unit)? = null
    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) {
            // Granted or not, the tunnel still works; only the status notification may be hidden.
            afterNotificationPermission?.invoke()
            afterNotificationPermission = null
        }
    private val vpnConsent =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            vm.onVpnConsentResult(it.resultCode == RESULT_OK)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Configs, names and the diagnostic report are on screen: keep them out of screenshots, screen
        // recording and the recents thumbnail (debug builds stay capturable for development).
        if (!BuildConfig.DEBUG) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        // A recreated activity (rotation, process death) gets the original launch intent again: do not re-offer it.
        if (savedInstanceState == null) handleIncoming(intent)
        setContent { WtTheme { Root() } }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIncoming(intent)
    }

    /** Links and shared text are never imported silently: the user confirms first. */
    private fun handleIncoming(intent: Intent?) {
        intent ?: return
        // Another app controls every field of this intent: a malformed extra must not crash the app.
        val text = try {
            Incoming.extract(
                intent.action, intent.data?.scheme, intent.data?.toString(),
                if (intent.action == Intent.ACTION_SEND) intent.getCharSequenceExtra(Intent.EXTRA_TEXT) else null,
            )
        } catch (e: Exception) {
            null
        }
        if (text != null) vm.offerExternal(ExternalImport.Text(text))
        // Consume so a rotation does not offer the same import again.
        if (intent.action == Intent.ACTION_VIEW || intent.action == Intent.ACTION_SEND) {
            intent.action = Intent.ACTION_MAIN
            intent.data = null
            intent.removeExtra(Intent.EXTRA_TEXT)
        }
    }

    private fun connect() {
        val needs = Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED &&
            !getSharedPreferences("wt_prefs", MODE_PRIVATE).getBoolean("notif_asked", false)
        if (needs) {
            getSharedPreferences("wt_prefs", MODE_PRIVATE).edit().putBoolean("notif_asked", true).apply()
            afterNotificationPermission = { vm.connect() }
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            vm.connect()
        }
    }

    private fun readUri(uri: Uri): ByteArray? = try {
        contentResolver.openInputStream(uri)?.use { input ->
            val out = java.io.ByteArrayOutputStream()
            val buf = ByteArray(16 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                out.write(buf, 0, n)
                if (out.size() > MAX_FILE) return null
            }
            out.toByteArray()
        }
    } catch (e: Exception) {
        null
    }

    @Composable
    private fun Root() {
        val state by TunnelState.state.collectAsStateWithLifecycle()
        val profiles by vm.profiles.collectAsStateWithLifecycle()
        val selected by vm.selectedId.collectAsStateWithLifecycle()
        val coreOk by vm.coreOk.collectAsStateWithLifecycle()
        val summary by vm.summary.collectAsStateWithLifecycle()
        val external by vm.pendingExternal.collectAsStateWithLifecycle()
        val subscription by vm.pendingSubscription.collectAsStateWithLifecycle()
        val ctx = LocalContext.current

        // Saveable so rotation or process recreation does not bounce the user back to the main screen.
        var showSettings by rememberSaveable { mutableStateOf(false) }
        var showAdd by rememberSaveable { mutableStateOf(false) }
        var renamingId by rememberSaveable { mutableStateOf<String?>(null) }
        var groupingId by rememberSaveable { mutableStateOf<String?>(null) }
        var deletingId by rememberSaveable { mutableStateOf<String?>(null) }
        val renaming = profiles.firstOrNull { it.id == renamingId }
        val grouping = profiles.firstOrNull { it.id == groupingId }
        val deleting = profiles.firstOrNull { it.id == deletingId }
        val snackbar = remember { SnackbarHostState() }

        LaunchedEffect(Unit) { vm.vpnConsent.collect { vpnConsent.launch(it) } }
        LaunchedEffect(state) { if (state is app.woodwardtunnel.vpn.ConnState.Disconnected) vm.onDisconnected() }
        LaunchedEffect(Unit) {
            vm.messages.collect { m ->
                snackbar.showSnackbar(ctx.getString(m.res, *m.args.toTypedArray()))
            }
        }

        val pickFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) importUri(uri)
        }
        val pickImage = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) importUri(uri)
        }
        val scan = rememberLauncherForActivityResult(ScanContract()) { r ->
            r.contents?.takeIf { it.length <= MAX_TEXT }?.let { vm.importText(it) }
        }

        BackHandler(enabled = showSettings) { showSettings = false }

        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            Scaffold(
                containerColor = MaterialTheme.colorScheme.background,
                snackbarHost = { SnackbarHost(snackbar, Modifier.navigationBarsPadding()) },
            ) { pad ->
                Column(Modifier.fillMaxSize().padding(pad), horizontalAlignment = androidx.compose.ui.Alignment.CenterHorizontally) {
                    if (showSettings) {
                        SettingsScreen(
                            onBack = { showSettings = false },
                            onSubscription = { vm.requestSubscription(it) },
                            onMessage = { vm.postMessage(it) },
                            activeProtocol = profiles.firstOrNull { it.id == selected }?.protocolName,
                        )
                    } else {
                        HomeScreen(
                            state = state, profiles = profiles, selectedId = selected, coreOk = coreOk,
                            onConnect = { if (state is app.woodwardtunnel.vpn.ConnState.Connected ||
                                state is app.woodwardtunnel.vpn.ConnState.Connecting ||
                                state is app.woodwardtunnel.vpn.ConnState.Reconnecting) vm.onConnectButton() else connect() },
                            onSelect = { vm.choose(it) },
                            onAdd = { showAdd = true },
                            onSettings = { showSettings = true },
                            onRename = { renamingId = it.id },
                            onGroup = { groupingId = it.id },
                            onDelete = { deletingId = it.id },
                        )
                    }
                }
            }
        }

        if (showAdd) {
            AlertDialog(
                onDismissRequest = { showAdd = false },
                title = { Text(stringResource(R.string.add_title)) },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        AddOption(R.string.add_clipboard) {
                            showAdd = false
                            val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            val t = cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(ctx)?.toString()
                            vm.importFromClipboard(t)
                        }
                        AddOption(R.string.add_file) { showAdd = false; pickFile.launch(arrayOf("*/*")) }
                        AddOption(R.string.add_qr) {
                            showAdd = false
                            scan.launch(
                                ScanOptions()
                                    .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                    .setPrompt(ctx.getString(R.string.qr_prompt))
                                    .setBeepEnabled(false)
                                    .setOrientationLocked(false),
                            )
                        }
                        AddOption(R.string.add_image) { showAdd = false; pickImage.launch(arrayOf("image/*")) }
                    }
                },
                confirmButton = { TextButton(onClick = { showAdd = false }) { Text(stringResource(R.string.action_cancel)) } },
            )
        }

        renaming?.let { p ->
            TextPrompt(R.string.action_rename, R.string.label_name, DisplayText.clean(p.name),
                onDismiss = { renamingId = null },
                onSave = { vm.rename(p.id, it); renamingId = null })
        }
        grouping?.let { p ->
            TextPrompt(R.string.action_group, R.string.label_group, p.group,
                onDismiss = { groupingId = null },
                onSave = { vm.setGroup(p.id, it); groupingId = null })
        }
        deleting?.let { p ->
            AlertDialog(
                onDismissRequest = { deletingId = null },
                text = {
                    ObscuredGuard()
                    Text(stringResource(R.string.delete_confirm, DisplayText.isolated(p.name)))
                },
                confirmButton = {
                    TextButton(onClick = { vm.delete(p.id); deletingId = null }) { Text(stringResource(R.string.action_delete)) }
                },
                dismissButton = { TextButton(onClick = { deletingId = null }) { Text(stringResource(R.string.action_cancel)) } },
            )
        }
        summary?.let { s ->
            AlertDialog(
                onDismissRequest = { vm.dismissSummary() },
                title = { Text(stringResource(R.string.import_problems_title)) },
                text = {
                    Column(
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                        modifier = Modifier.verticalScroll(rememberScrollState()),
                    ) {
                        if (s.added > 0) Text(stringResource(R.string.import_added, s.added))
                        if (s.duplicates > 0) Text(stringResource(R.string.import_duplicates, s.duplicates))
                        Text(stringResource(R.string.import_problems_count, s.problems.size), fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold)
                        s.problems.take(MAX_PROBLEMS_SHOWN).forEach { msg ->
                            Text(DisplayText.clean(msg, 300), style = MaterialTheme.typography.bodySmall)
                        }
                        if (s.problems.size > MAX_PROBLEMS_SHOWN) {
                            Text(stringResource(R.string.import_problems_more, s.problems.size - MAX_PROBLEMS_SHOWN), style = MaterialTheme.typography.bodySmall)
                        }
                    }
                },
                confirmButton = { TextButton(onClick = { vm.dismissSummary() }) { Text(stringResource(R.string.action_ok)) } },
            )
        }
        external?.let { ext ->
            val preview = remember(ext) { (ext as? ExternalImport.Text)?.let { Incoming.preview(it.text) } }
            AlertDialog(
                onDismissRequest = { vm.declineExternal() },
                title = { Text(stringResource(R.string.external_import_title)) },
                text = {
                    ObscuredGuard()
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(stringResource(R.string.external_import_body))
                        if (preview != null && preview.links > 0) {
                            Text(
                                stringResource(R.string.external_import_preview, preview.links, preview.schemes.joinToString(", ")),
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    }
                },
                confirmButton = { TextButton(onClick = { vm.confirmExternal() }) { Text(stringResource(R.string.action_add)) } },
                dismissButton = { TextButton(onClick = { vm.declineExternal() }) { Text(stringResource(R.string.action_cancel)) } },
            )
        }
        subscription?.let { url ->
            AlertDialog(
                onDismissRequest = { vm.declineSubscription() },
                title = { Text(stringResource(R.string.subscription_title)) },
                text = {
                    ObscuredGuard()
                    Text(stringResource(R.string.subscription_body, MainViewModel.hostOf(url)))
                },
                confirmButton = { TextButton(onClick = { vm.confirmSubscription() }) { Text(stringResource(R.string.subscription_download)) } },
                dismissButton = { TextButton(onClick = { vm.declineSubscription() }) { Text(stringResource(R.string.action_cancel)) } },
            )
        }
    }

    private fun importUri(uri: Uri) {
        // Reading (up to 8 MB) must not block the main thread.
        vm.viewModelScope.launch(kotlinx.coroutines.Dispatchers.IO) {
            val bytes = readUri(uri)
            if (bytes == null) vm.postMessage(R.string.import_read_failed) else vm.importBytes(bytes)
        }
    }

    @Composable
    private fun AddOption(label: Int, onClick: () -> Unit) {
        OutlinedButton(onClick = onClick, modifier = Modifier.fillMaxWidth()) { Text(stringResource(label)) }
    }

    @Composable
    private fun TextPrompt(title: Int, label: Int, initial: String, onDismiss: () -> Unit, onSave: (String) -> Unit) {
        var text by rememberSaveable { mutableStateOf(initial) }
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(stringResource(title)) },
            text = {
                OutlinedTextField(
                    value = text, onValueChange = { text = it.take(80) }, singleLine = true,
                    label = { Text(stringResource(label)) },
                )
            },
            confirmButton = { Button(onClick = { onSave(text) }) { Text(stringResource(R.string.action_save)) } },
            dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) } },
        )
    }

    private companion object {
        const val MAX_TEXT = Incoming.MAX_TEXT
        const val MAX_PROBLEMS_SHOWN = 30
        const val MAX_FILE = 8 * 1024 * 1024
    }
}

/** Drops touches that arrive while another app draws over this dialog (tapjacking). */
@Composable
fun ObscuredGuard() {
    val v = androidx.compose.ui.platform.LocalView.current
    androidx.compose.runtime.SideEffect { v.rootView.filterTouchesWhenObscured = true }
}
