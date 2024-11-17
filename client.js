const io = require("socket.io-client"); // untuk membuat web socket (versi client)
const readline = require("readline"); // untuk mengambil inputan user
const crypto = require("crypto"); // untuk membuat/memverifikasi key dan signature

const socket = io("http://localhost:3000"); // url dimana server running

// setup RSA keys untuk client
const options = {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
};
const { privateKey: clientPrivateKey, publicKey: clientPublicKey } = crypto.generateKeyPairSync("rsa", options);

const rl = readline.createInterface({ // setup readline, membuat object dengan parameter input, output, dan prompt
    input: process.stdin, // mengarahkan input dari terminal
    output: process.stdout, // mengarahkan output dari terminal
    prompt: "> " // tampilan prompt di terminal
});

let registeredUsername = ""; // username asli
let username = ""; // username yang dipakai
const users = new Map(); // untuk menyimpan username dan public key user

socket.on("connect", () => { // dijalankan ketika socket terkoneksi dengan server
    console.log("Connected to the server");

    rl.question("Enter your username: ", (input) => { // untuk menanyakan username client menggunakan library rl dan fungsi question
        username = input; // menyimpan input user dalam variabel username
        registeredUsername = input;
        console.log(`Welcome, ${username} to the chat`);

        socket.emit("registerPublicKey", {
            username, 
            publicKey: clientPublicKey
        }); // mengirim public key user ke server

        rl.prompt(); // untuk memunculkan prompt

        rl.on("line", (message) => { // dijalankan ketika user menekan enter, message adalah inputan sebelum user menekan enter
            if (message.trim()) { // untuk menghapus spasi di sesudah dan sebelum message
                if ((match = message.match(/^!impersonate (\w+)$/))) { // regex agar user dapat mengimpersonate user lain
                    username = match[1];
                    console.log(`Now impersonating as ${username}`);
                } else if (message.match(/^!exit$/)) { // regex untuk kembali menjadi user yang asli
                    username = registeredUsername;
                    console.log(`Now you are ${username}`);
                } else {
                    const data = Buffer.from(message);
                    const signature = crypto.sign("sha256", data, clientPrivateKey).toString("hex"); // membuat signature dari message yang akan dikirim
                    socket.emit("message", { username, message, signature }); // mengirim username, message, dan signature ke server 
                    // message adalah channelnya - username, message, dan signature adalah object dari inputan user
                }
            }
            rl.prompt(); // menampilkan kembali prompt
        });
    });
});

socket.on("init", (keys) => {
    keys.forEach(([user, key]) => users.set(user, key));
    console.log(`\nThere are currently ${users.size} users in the chat`);
    rl.prompt();
}); // menerima user dan public key dari server dan menyimpannya di dalam map users

socket.on("newUser", (data) => {
    const { username, publicKey } = data;
    users.set(username, publicKey); // mengupdate Map users dengan username dan public key user yang baru
    console.log(`${username} joined the chat`); // menampilkan join message
    rl.prompt();
}); 

socket.on("message", (data) => {
    const { username: senderUsername, message: senderMessage, signature } = data; // menerima data dari server

    if(senderUsername !== username) { // memfilter agar client tidak menerima pesan yang dikirimkan oleh dirinya sendiri
        const senderPublicKey = users.get(senderUsername);
        if (senderPublicKey) {
            const isValid = crypto.verify("sha256", Buffer.from(senderMessage), senderPublicKey, Buffer.from(signature, "hex"));
            if (isValid) {
                console.log(`${senderUsername}: ${senderMessage}`);
            } else {
                console.log(`${senderUsername}: ${senderMessage}\nWARNING: This user is fake.`);
            }
        } else {
            console.log(`${senderUsername}: ${senderMessage}\nWARNING: Public key not found for this user.`);
        }
        rl.prompt();
    }
});

socket.on("disconnect", () => { // dijalankan ketika socket disconnect (server disconnect atau server menekan Ctrl + C)
    console.log("Server disconnected, Exiting...");
    rl.close();
    process.exit(0);
});

rl.on("SIGINT", () => { // command signal interrupt (SIGINT), dijalankan ketika client menekan Ctrl + C
    console.log("\nExiting...");
    socket.disconnect(); // menutup socket yang terbuka
    rl.close(); // menutup rl yang terbuka
    process.exit(0); // menutup proses node.js, 0 adalah kode error
});