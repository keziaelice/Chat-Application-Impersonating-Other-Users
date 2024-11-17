const http = require("http"); // untuk membuat http server menggunakan library bawaan node.js (http)
const socketIo = require("socket.io"); // untuk membuat web socket

const server = http.createServer(); // mengkoneksikan atau membuat http server
const io = socketIo(server); // io adalah web server yang sudah terkoneksi dengan socket.io

const users = new Map(); // untuk menyimpan username dan public key user

io.on("connection", (socket) => { // dijalankan ketika ada client yang terkoneksi dengan server (1 client punya 1 socket)
    console.log(`Client ${socket.id} connected`); // socket.id adalah id untuk membedakan socket client 1 dengan client lain

    socket.emit("init", Array.from(users.entries())); // mengirim seluruh username dan public key yang sudah tersimpan kepada client baru

    socket.on("registerPublicKey", (data) => {
        const { username, publicKey } = data;
        users.set(username, publicKey);
        console.log(`${username} registered with public key.`);
        io.emit("newUser", { username, publicKey }); // broadcast notifikasi username dan public key dari newUser ke semua user yang sedang terkoneksi dengan socket
    }); // mengambil username dan public key user untuk disimpan

    socket.on("message", (data) => { // membuat channel message untuk menerima data dari channel/socket message
        let { username, message, signature } = data;
        console.log(`Receiving message from ${username}: ${message}`); // memeriksa apakah data sudah masuk
        io.emit("message", data); // mengirim ulang data ke client dengan masuk ke channel message 
        // (semua socket id yang sudah terkoneksi dengan io akan menerima pesan)
    });

    socket.on("disconnect", () => { // dijalankan ketika ada client yang disconnect
        console.log(`Client ${socket.id} disconnected`);
    });
});

const port = 3000; // port dimana server bekerja
server.listen(port, () => { // untuk membuka koneksi port (server akan mendengarkan semua request dengan port 3000)
    console.log(`Server running on port ${port}`)
});