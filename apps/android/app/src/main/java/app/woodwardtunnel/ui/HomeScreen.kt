package app.woodwardtunnel.ui

import android.os.SystemClock
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.clickable
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.OutlinedTextField
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.woodwardtunnel.R
import app.woodwardtunnel.vpn.ConnState
import app.woodwardtunnel.vpn.Limit
import kotlinx.coroutines.delay
import uniffi.wtcore.FfiProfile
import java.util.Locale

@Composable
fun HomeScreen(
    state: ConnState,
    profiles: List<FfiProfile>,
    selectedId: String?,
    coreOk: Boolean,
    onConnect: () -> Unit,
    onSelect: (String) -> Unit,
    onAdd: () -> Unit,
    onSettings: () -> Unit,
    onRename: (FfiProfile) -> Unit,
    onGroup: (FfiProfile) -> Unit,
    onDelete: (FfiProfile) -> Unit,
) {
    var query by rememberSaveable { mutableStateOf("") }
    val showSearch = profiles.size > SEARCH_THRESHOLD
    val q = query.trim()
    val visible = remember(profiles, q, showSearch) {
        if (!showSearch || q.isEmpty()) profiles
        else profiles.filter {
            DisplayText.clean(it.name).contains(q, ignoreCase = true) ||
                DisplayText.clean(it.group).contains(q, ignoreCase = true) ||
                it.protocolName.contains(q, ignoreCase = true)
        }
    }
    // Groups appear in order of first use; ungrouped profiles come last.
    val grouped = remember(visible) {
        val named = visible.filter { it.group.isNotBlank() }.groupBy { DisplayText.clean(it.group) }
        val loose = visible.filter { it.group.isBlank() }
        named to loose
    }
    // Tablets and landscape: keep a phone-width column instead of stretching rows across the screen.
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
    LazyColumn(
        modifier = Modifier.widthIn(max = 640.dp).fillMaxSize().statusBarsPadding(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 20.dp, vertical = 8.dp),
    ) {
        item {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    stringResource(R.string.app_name),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f).semantics { heading() },
                )
                IconButton(onClick = onSettings) {
                    Icon(Icons.Filled.Settings, contentDescription = stringResource(R.string.action_settings))
                }
            }
        }
        item { ConnectPanel(state, coreOk, profiles.isNotEmpty(), onConnect) }
        item {
            Row(
                Modifier.fillMaxWidth().padding(top = 24.dp, bottom = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    stringResource(R.string.profiles_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.weight(1f).semantics { heading() },
                )
                FilledTonalButton(onClick = onAdd) {
                    Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(stringResource(R.string.action_add))
                }
            }
        }
        if (profiles.isEmpty()) {
            item {
                Text(
                    stringResource(R.string.profiles_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                    modifier = Modifier.padding(vertical = 24.dp).fillMaxWidth(),
                    textAlign = TextAlign.Center,
                )
            }
        }
        if (showSearch) {
            item {
                OutlinedTextField(
                    value = query, onValueChange = { query = it.take(80) }, singleLine = true,
                    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                    placeholder = { Text(stringResource(R.string.search_hint)) },
                    modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                )
                Text(
                    stringResource(R.string.profiles_count, visible.size, profiles.size),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                )
            }
            if (visible.isEmpty()) {
                item {
                    Text(
                        stringResource(R.string.search_none),
                        modifier = Modifier.padding(vertical = 24.dp).fillMaxWidth(),
                        textAlign = TextAlign.Center,
                    )
                }
            }
        }
        grouped.first.forEach { (group, list) ->
            item(key = "group:$group") {
                Text(
                    DisplayText.isolated(group), style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(top = 12.dp, bottom = 2.dp).semantics { heading() },
                )
            }
            items(list, key = { it.id }) { p -> row(p, selectedId, onSelect, onRename, onGroup, onDelete) }
        }
        if (grouped.second.isNotEmpty()) {
            if (grouped.first.isNotEmpty()) {
                item(key = "group:none") {
                    Text(
                        stringResource(R.string.group_none), style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(top = 12.dp, bottom = 2.dp).semantics { heading() },
                    )
                }
            }
            items(grouped.second, key = { it.id }) { p -> row(p, selectedId, onSelect, onRename, onGroup, onDelete) }
        }
        item { Spacer(Modifier.height(32.dp)) }
    }
    }
}

private const val SEARCH_THRESHOLD = 6

@Composable
private fun row(
    p: FfiProfile, selectedId: String?, onSelect: (String) -> Unit,
    onRename: (FfiProfile) -> Unit, onGroup: (FfiProfile) -> Unit, onDelete: (FfiProfile) -> Unit,
) = ProfileRow(
    p, p.id == selectedId,
    onClick = { onSelect(p.id) },
    onRename = { onRename(p) }, onGroup = { onGroup(p) }, onDelete = { onDelete(p) },
)

@Composable
private fun ConnectPanel(state: ConnState, coreOk: Boolean, hasProfiles: Boolean, onConnect: () -> Unit) {
    val color = when (state) {
        is ConnState.Connected -> StateColors.connected
        is ConnState.Connecting, is ConnState.Reconnecting -> StateColors.connecting
        is ConnState.Error -> StateColors.error
        else -> StateColors.idle
    }
    val title = when (state) {
        is ConnState.Connected -> R.string.state_connected
        is ConnState.Connecting -> R.string.state_connecting
        is ConnState.Reconnecting -> R.string.state_reconnecting
        is ConnState.Error -> R.string.state_error
        else -> R.string.state_disconnected
    }
    Column(
        Modifier.fillMaxWidth().padding(top = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        val cd = stringResource(
            when (state) {
                is ConnState.Connected -> R.string.cd_disconnect
                is ConnState.Connecting, is ConnState.Reconnecting -> R.string.cd_cancel
                else -> R.string.cd_connect
            },
        )
        val stateText = stringResource(title)
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .size(176.dp)
                .clip(CircleShape)
                .clickable(enabled = coreOk, role = Role.Button, onClick = onConnect)
                .semantics {
                    contentDescription = cd
                    stateDescription = stateText
                },
        ) {
            Surface(shape = CircleShape, color = color.copy(alpha = 0.14f), modifier = Modifier.fillMaxSize()) {}
            Surface(
                shape = CircleShape, color = color, modifier = Modifier.size(132.dp),
                shadowElevation = 6.dp,
            ) {
                Box(contentAlignment = Alignment.Center) {
                    PowerGlyph(Color.White)
                }
            }
            if (state is ConnState.Connecting || state is ConnState.Reconnecting) {
                CircularProgressIndicator(
                    modifier = Modifier.size(168.dp), color = color, strokeWidth = 4.dp,
                )
            }
        }
        Spacer(Modifier.height(16.dp))
        Text(
            stringResource(title),
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
            color = color,
            // Screen readers announce every state change (connected, failed ...) without focus moving.
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
        )
        Spacer(Modifier.height(6.dp))
        when (state) {
            is ConnState.Connected -> {
                ElapsedTimer(state.sinceElapsed)
                if (state.insecureTls) {
                    Text(
                        stringResource(R.string.warn_insecure),
                        style = MaterialTheme.typography.bodySmall,
                        color = StateColors.connecting,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(top = 8.dp, start = 16.dp, end = 16.dp),
                    )
                }
                for (limit in state.limits) {
                    Text(
                        stringResource(limit.messageRes()),
                        style = MaterialTheme.typography.bodySmall,
                        color = StateColors.connecting,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(top = 6.dp, start = 16.dp, end = 16.dp),
                    )
                }
                Hint(R.string.hint_disconnect)
            }
            is ConnState.Reconnecting -> {
                Hint(R.string.hint_reconnecting)
                TextButton(onClick = onConnect) { Text(stringResource(R.string.action_cancel_connect)) }
            }
            is ConnState.Connecting -> {
                Hint(R.string.hint_connecting)
                TextButton(onClick = onConnect) { Text(stringResource(R.string.action_cancel_connect)) }
            }
            is ConnState.Error -> {
                Text(
                    state.coreMessage ?: stringResource(state.message),
                    style = MaterialTheme.typography.bodyMedium,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(horizontal = 16.dp).semantics { liveRegion = LiveRegionMode.Polite },
                )
                Spacer(Modifier.height(8.dp))
                Button(onClick = onConnect) { Text(stringResource(R.string.action_retry)) }
                Text(
                    stringResource(R.string.trouble_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(top = 12.dp, start = 20.dp, end = 20.dp),
                )
            }
            else -> Hint(if (hasProfiles) R.string.hint_connect else R.string.hint_add_first)
        }
        if (!coreOk) {
            Text(
                stringResource(R.string.err_storage),
                color = StateColors.error,
                modifier = Modifier.padding(top = 8.dp),
                textAlign = TextAlign.Center,
            )
        }
    }
}

@Composable
private fun Hint(res: Int) {
    Text(
        stringResource(res),
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.65f),
    )
}

@Composable
private fun ElapsedTimer(since: Long) {
    var now by remember { mutableLongStateOf(SystemClock.elapsedRealtime()) }
    LaunchedEffect(since) {
        while (true) {
            now = SystemClock.elapsedRealtime()
            delay(1000)
        }
    }
    val total = ((now - since) / 1000).coerceAtLeast(0)
    Text(
        // LRM keeps the digits in reading order inside a right-to-left layout.
        "\u200E" + String.format(Locale.getDefault(), "%02d:%02d:%02d", total / 3600, total / 60 % 60, total % 60),
        style = MaterialTheme.typography.titleLarge,
        fontSize = 26.sp,
    )
}

@Composable
private fun PowerGlyph(tint: Color) {
    Canvas(Modifier.size(52.dp)) {
        val stroke = Stroke(width = 5.dp.toPx(), cap = StrokeCap.Round)
        val inset = 5.dp.toPx()
        drawArc(
            color = tint, startAngle = -60f, sweepAngle = 300f, useCenter = false,
            topLeft = Offset(inset, inset * 1.6f), size = Size(size.width - 2 * inset, size.width - 2 * inset),
            style = stroke,
        )
        drawLine(tint, Offset(size.width / 2, 2.dp.toPx()), Offset(size.width / 2, size.height * 0.45f), 5.dp.toPx(), StrokeCap.Round)
    }
}

@Composable
private fun ProfileRow(
    p: FfiProfile,
    selected: Boolean,
    onClick: () -> Unit,
    onRename: () -> Unit,
    onGroup: () -> Unit,
    onDelete: () -> Unit,
) {
    var menu by remember { mutableStateOf(false) }
    val name = DisplayText.clean(p.name).ifBlank { p.protocolName }
    val moreCd = stringResource(R.string.cd_profile_options, name)
    Card(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = if (selected) BorderStroke(2.dp, MaterialTheme.colorScheme.primary) else null,
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            // One focus target for TalkBack: the row is the radio button, the menu is a separate button.
            Row(
                Modifier.weight(1f)
                    .selectable(selected = selected, role = Role.RadioButton, onClick = onClick)
                    .padding(start = 8.dp, top = 6.dp, bottom = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = selected, onClick = null, modifier = Modifier.padding(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        "\u2068$name\u2069", style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Medium, maxLines = 1, overflow = TextOverflow.Ellipsis,
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Badge(p.protocolName)
                        if (p.group.isNotBlank()) {
                            Spacer(Modifier.width(8.dp))
                            Text(
                                DisplayText.isolated(p.group, 40),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                                maxLines = 1, overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }
            }
            Box {
                IconButton(onClick = { menu = true }) {
                    Icon(Icons.Filled.MoreVert, contentDescription = moreCd)
                }
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                    DropdownMenuItem(text = { Text(stringResource(R.string.action_rename)) }, onClick = { menu = false; onRename() })
                    DropdownMenuItem(text = { Text(stringResource(R.string.action_group)) }, onClick = { menu = false; onGroup() })
                    DropdownMenuItem(text = { Text(stringResource(R.string.action_delete)) }, onClick = { menu = false; onDelete() })
                }
            }
        }
    }
}

@Composable
private fun Badge(text: String) {
    Surface(shape = RoundedCornerShape(6.dp), color = MaterialTheme.colorScheme.surfaceVariant) {
        Text(
            text,
            style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
        )
    }
}

private fun Limit.messageRes(): Int = when (this) {
    Limit.DNS_PARTIAL -> R.string.limit_dns_partial
    Limit.HTTPS_PARTIAL -> R.string.limit_https_partial
    Limit.UDP -> R.string.limit_udp
    Limit.SAME_EGRESS -> R.string.limit_same_egress
    Limit.UNVERIFIED -> R.string.limit_unverified
}
