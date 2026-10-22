# gomobile / libbox: classes are called from native code by name.
-keep class go.** { *; }
-keep class io.nekohasekai.libbox.** { *; }
# JNA + UniFFI bindings are resolved reflectively.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class uniffi.** { *; }
-dontwarn java.awt.**
-dontwarn com.sun.jna.**
