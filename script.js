"use strict";

var encoder = new TextEncoder();
var decoder = new TextDecoder("utf-8", { fatal: true });

// Convert bytes to Base64 text.
function toBase64(bytes) {
    var binary = "";

    bytes.forEach(function (byte) {
        binary += String.fromCharCode(byte);
    });

    return btoa(binary);
}

// Convert Base64 text back to bytes.
function fromBase64(text) {
    var binary = atob(text);
    var bytes = new Uint8Array(binary.length);

    for (var i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}

// Derive an AES-256 key from the user's secret code.
async function createKey(secretCode, salt) {
    var material = await crypto.subtle.importKey(
        "raw",
        encoder.encode(secretCode),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 250000,
            hash: "SHA-256"
        },
        material,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}

// Encrypt a plain-text message.
async function encryptMessage(message, secretCode) {
    var salt = crypto.getRandomValues(new Uint8Array(16));
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var key = await createKey(secretCode, salt);

    var ciphertext = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        encoder.encode(message)
    );

    // Format: version.salt.iv.ciphertext
    return [
        "CRYPTA1",
        toBase64(salt),
        toBase64(iv),
        toBase64(new Uint8Array(ciphertext))
    ].join(".");
}

// Decrypt an encrypted message.
async function decryptMessage(encryptedText, secretCode) {
    var parts = encryptedText.trim().split(".");

    if (parts.length !== 4 || parts[0] !== "CRYPTA1") {
        throw new Error("Invalid encrypted text format.");
    }

    var salt = fromBase64(parts[1]);
    var iv = fromBase64(parts[2]);
    var ciphertext = fromBase64(parts[3]);

    if (
        salt.length !== 16 ||
        iv.length !== 12 ||
        ciphertext.length < 16
    ) {
        throw new Error("The encrypted text is incomplete or invalid.");
    }

    var key = await createKey(secretCode, salt);

    var plaintext = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        ciphertext
    );

    return decoder.decode(plaintext);
}

// Show a status message.
function setStatus(id, message, isError) {
    var element = document.getElementById(id);

    element.textContent = message;
    element.style.color = isError ? "#fca5a5" : "#86efac";
}

// Copy text using the Clipboard API, with a fallback.
async function copyOutput(outputId, statusId) {
    var output = document.getElementById(outputId);
    var text = output.value;
    var status = document.getElementById(statusId);

    try {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
        } else {
            output.focus();
            output.select();

            var copied = document.execCommand("copy");

            if (!copied) {
                throw new Error("Manual copy required.");
            }

            output.setSelectionRange(0, 0);
        }

        setStatus(statusId, "Text copied successfully.", false);
    } catch (error) {
        status.textContent = "Select the text and copy it manually.";
        output.focus();
        output.select();
    }
}

// Sender page logic.
var senderForm = document.getElementById("senderForm");

if (senderForm) {
    senderForm.addEventListener("submit", async function (event) {
        event.preventDefault();

        var code = document.getElementById("senderCode").value;
        var message = document.getElementById("message").value;
        var button = document.getElementById("encryptBtn");
        var result = document.getElementById("encryptedResult");
        var output = document.getElementById("encryptedOutput");

        result.hidden = true;
        output.value = "";
        setStatus("senderStatus", "", false);

        if (code.length < 8) {
            setStatus(
                "senderStatus",
                "Your secret code must contain at least 8 characters.",
                true
            );
            return;
        }

        if (!message.trim()) {
            setStatus("senderStatus", "Enter a text message.", true);
            return;
        }

        if (!window.crypto || !crypto.subtle) {
            setStatus(
                "senderStatus",
                "Secure encryption is unavailable. Open this app using localhost or HTTPS.",
                true
            );
            return;
        }

        button.disabled = true;
        button.textContent = "Encrypting...";

        try {
            var encryptedText = await encryptMessage(message, code);

            output.value = encryptedText;
            result.hidden = false;

            setStatus("senderStatus", "Message encrypted successfully.", false);
        } catch (error) {
            console.error("Encryption error:", error);

            setStatus(
                "senderStatus",
                "Encryption failed: " + error.message,
                true
            );
        } finally {
            button.disabled = false;
            button.textContent = "Encrypt Message";
        }
    });
}

// Receiver page logic.
var receiverForm = document.getElementById("receiverForm");

if (receiverForm) {
    receiverForm.addEventListener("submit", async function (event) {
        event.preventDefault();

        var code = document.getElementById("receiverCode").value;
        var encryptedText =
            document.getElementById("encryptedMessage").value;

        var button = document.getElementById("decryptBtn");
        var result = document.getElementById("decryptedResult");
        var output = document.getElementById("decryptedOutput");

        result.hidden = true;
        output.value = "";
        setStatus("receiverStatus", "", false);

        if (code.length < 8) {
            setStatus(
                "receiverStatus",
                "Enter the secret code with at least 8 characters.",
                true
            );
            return;
        }

        if (!encryptedText.trim()) {
            setStatus("receiverStatus", "Paste the encrypted text.", true);
            return;
        }

        if (!window.crypto || !crypto.subtle) {
            setStatus(
                "receiverStatus",
                "Secure decryption is unavailable. Open this app using localhost or HTTPS.",
                true
            );
            return;
        }

        button.disabled = true;
        button.textContent = "Decrypting...";

        try {
            var originalMessage = await decryptMessage(
                encryptedText,
                code
            );

            output.value = originalMessage;
            result.hidden = false;

            setStatus(
                "receiverStatus",
                "Message decrypted successfully.",
                false
            );
        } catch (error) {
            console.error("Decryption error:", error);

            setStatus(
                "receiverStatus",
                "Decryption failed. Check the secret code and encrypted text.",
                true
            );
        } finally {
            button.disabled = false;
            button.textContent = "Decrypt Message";
        }
    });
}

// Sender copy button.
var copyBtn = document.getElementById("copyBtn");

if (copyBtn) {
    copyBtn.addEventListener("click", function () {
        copyOutput("encryptedOutput", "senderStatus");
    });
}

// Receiver copy button.
var copyPlainBtn = document.getElementById("copyPlainBtn");

if (copyPlainBtn) {
    copyPlainBtn.addEventListener("click", function () {
        copyOutput("decryptedOutput", "receiverStatus");
    });
}