package app.woodwardtunnel.vpn

/**
 * Small in-memory ring buffer of recent engine and app events for the diagnostic report. Memory only:
 * never written to disk or logcat. Lines may contain engine text; the Rust core redacts them again when it
 * builds the report, and the user reads the report before sharing it.
 */
object EngineLog {
    private const val MAX = 200
    private val lines = ArrayDeque<String>()

    @Synchronized
    fun add(line: String) {
        if (lines.size >= MAX) lines.removeFirst()
        lines.addLast(line.take(500))
    }

    @Synchronized
    fun snapshot(): List<String> = lines.toList()
}
