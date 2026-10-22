package app.woodwardtunnel.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val Teal = Color(0xFF0F4C5C)
private val Mint = Color(0xFF2E9E78)

private val Light = lightColorScheme(
    primary = Teal,
    onPrimary = Color.White,
    secondary = Mint,
    background = Color(0xFFF4F7FA),
    surface = Color.White,
    surfaceVariant = Color(0xFFE6EDF2),
    error = Color(0xFFB3261E),
)

private val Dark = darkColorScheme(
    primary = Color(0xFF7FD1AE),
    onPrimary = Color(0xFF00382A),
    secondary = Color(0xFF7FD1AE),
    background = Color(0xFF0E1417),
    surface = Color(0xFF172025),
    surfaceVariant = Color(0xFF25323A),
    error = Color(0xFFF2B8B5),
)

object StateColors {
    val connected = Color(0xFF2E9E78)
    val connecting = Color(0xFFE0A100)
    val idle = Color(0xFF5F7A8A)
    val error = Color(0xFFC0392B)
}

@Composable
fun WtTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) Dark else Light, content = content)
}
