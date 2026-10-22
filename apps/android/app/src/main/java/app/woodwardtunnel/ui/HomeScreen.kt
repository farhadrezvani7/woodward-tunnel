package app.woodwardtunnel.ui

import android.os.SystemClock
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.clickable
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
    LazyColumn(
        modifier = Modifier.fillMaxSize().statusBarsPadding(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 20.dp, vertical = 8.dp),
    ) {
        item {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    stringResource(R.string.app_name),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f),
                )
                IconButton(onClick = onSettings) {
                    Icon(Icons.Filled.Settings, contentDescription = stringResource(R.string.action_settings))
                }
            }
        }
        item { ConnectPanel(state, coreOk, onConnect) }
        item {
            Row(
                Modifier.fillMaxWidth().padding(top = 24.dp, bottom = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    stringResource(R.string.profiles_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.weight(1f),
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
        items(profiles, key = { it.id }) { p ->
            ProfileRow(
                p, p.id == selectedId,
                onClick = { onSelect(p.id) },
                onRename = { onRename(p) }, onGroup = { onGroup(p) }, onDelete = { onDelete(p) },
            )
        }
        item { Spacer(Modifier.height(32.dp)) }
    }
}

@Composable
private fun ConnectPanel(state: ConnState, coreOk: Boolean, onConnect: () -> Unit) {
    val color = when (state) {
        is ConnState.Connected -> StateColors.connected
        is ConnState.Connecting -> StateColors.connecting
        is ConnState.Error -> StateColors.error
        else -> StateColors.idle
    }
    val title = when (state) {
        is ConnState.Connected -> R.string.state_connected
        is ConnState.Connecting -> R.string.state_connecting
        is ConnState.Error -> R.string.state_error
        else -> R.string.state_disconnected
    }
    Column(
        Modifier.fillMaxWidth().padding(top = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        val cd = stringResource(R.string.cd_connect_button)
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .size(176.dp)
                .clip(CircleShape)
                .clickable(enabled = coreOk, onClick = onConnect)
                .semantics { contentDescription = cd },
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
            if (state is ConnState.Connecting) {
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
                Hint(R.string.hint_disconnect)
            }
            is ConnState.Connecting -> Hint(R.string.hint_connecting)
            is ConnState.Error -> {
                Text(
                    state.coreMessage ?: stringResource(state.message),
                    style = MaterialTheme.typography.bodyMedium,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(horizontal = 16.dp),
                )
                Spacer(Modifier.height(8.dp))
                Button(onClick = onConnect) { Text(stringResource(R.string.action_retry)) }
            }
            else -> Hint(R.string.hint_connect)
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
    Card(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp).clickable(onClick = onClick),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = if (selected) BorderStroke(2.dp, MaterialTheme.colorScheme.primary) else null,
    ) {
        Row(Modifier.padding(horizontal = 8.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = selected, onClick = onClick)
            Column(Modifier.weight(1f)) {
                Text(p.name, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium, maxLines = 1)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Badge(p.protocolName)
                    if (p.group.isNotBlank()) {
                        Spacer(Modifier.width(8.dp))
                        Text(
                            p.group,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                            maxLines = 1,
                        )
                    }
                }
            }
            Box {
                TextButton(onClick = { menu = true }) { Text("⋮", fontSize = 20.sp) }
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
