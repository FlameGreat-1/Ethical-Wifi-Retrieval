import java.io.File
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

class Obfuscator {
    private val key = "ThisIsASecretKey".toByteArray()
    private val algorithm = "AES"

    fun obfuscate(sourceDir: String, outputDir: String) {
        val sourceFile = File(sourceDir)
        val outputFile = File(outputDir)

        if (!sourceFile.exists() || !sourceFile.isDirectory) {
            throw IllegalArgumentException("Source directory does not exist or is not a directory")
        }

        outputFile.mkdirs()

        sourceFile.walkTopDown().forEach { file ->
            if (file.isFile) {
                val relativePath = file.relativeTo(sourceFile)
                val outputPath = File(outputFile, relativePath.path)
                outputPath.parentFile.mkdirs()

                val obfuscatedContent = obfuscateFile(file)
                outputPath.writeBytes(obfuscatedContent)
            }
        }
    }

    private fun obfuscateFile(file: File): ByteArray {
        val content = file.readBytes()
        return when (file.extension.toLowerCase()) {
            "java", "kt", "xml" -> obfuscateCode(content)
            else -> obfuscateBinary(content)
        }
    }

    private fun obfuscateCode(content: ByteArray): ByteArray {
        val contentString = String(content)
        val obfuscatedString = contentString
            .replace("public", "p${randomString(5)}")
            .replace("private", "pr${randomString(4)}")
            .replace("protected", "pro${randomString(3)}")
            .replace("class", "c${randomString(5)}")
            .replace("interface", "i${randomString(4)}")
            .replace("extends", "e${randomString(5)}")
            .replace("implements", "im${randomString(3)}")
        return obfuscatedString.toByteArray()
    }

    private fun obfuscateBinary(content: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(algorithm)
        val secretKey = SecretKeySpec(key, algorithm)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipher.doFinal(content)
    }

    private fun randomString(length: Int): String {
        val charPool: List<Char> = ('a'..'z') + ('A'..'Z') + ('0'..'9')
        return (1..length)
            .map { Random.nextInt(0, charPool.size) }
            .map(charPool::get)
            .joinToString("")
    }

    fun deobfuscate(obfuscatedDir: String, outputDir: String) {
        val obfuscatedFile = File(obfuscatedDir)
        val outputFile = File(outputDir)

        if (!obfuscatedFile.exists() || !obfuscatedFile.isDirectory) {
            throw IllegalArgumentException("Obfuscated directory does not exist or is not a directory")
        }

        outputFile.mkdirs()

        obfuscatedFile.walkTopDown().forEach { file ->
            if (file.isFile) {
                val relativePath = file.relativeTo(obfuscatedFile)
                val outputPath = File(outputFile, relativePath.path)
                outputPath.parentFile.mkdirs()

                val deobfuscatedContent = deobfuscateFile(file)
                outputPath.writeBytes(deobfuscatedContent)
            }
        }
    }

    private fun deobfuscateFile(file: File): ByteArray {
        val content = file.readBytes()
        return when (file.extension.toLowerCase()) {
            "java", "kt", "xml" -> deobfuscateCode(content)
            else -> deobfuscateBinary(content)
        }
    }

    private fun deobfuscateCode(content: ByteArray): ByteArray {
    val contentString = String(content)
    val deobfuscatedString = contentString
        .replace(Regex("p[a-zA-Z0-9]{5}\\b"), "public")
        .replace(Regex("pr[a-zA-Z0-9]{4}\\b"), "private")
        .replace(Regex("pro[a-zA-Z0-9]{3}\\b"), "protected")
        .replace(Regex("c[a-zA-Z0-9]{5}\\b"), "class")
        .replace(Regex("i[a-zA-Z0-9]{4}\\b"), "interface")
        .replace(Regex("e[a-zA-Z0-9]{5}\\b"), "extends")
        .replace(Regex("im[a-zA-Z0-9]{3}\\b"), "implements")

    return deobfuscatedString.toByteArray()
}

    }

    private fun deobfuscateBinary(content: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(algorithm)
        val secretKey = SecretKeySpec(key, algorithm)
        cipher.init(Cipher.DECRYPT_MODE, secretKey)
        return cipher.doFinal(content)
    }

    fun computeHash(dir: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        File(dir).walkTopDown().forEach { file ->
            if (file.isFile) {
                digest.update(file.readBytes())
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}
