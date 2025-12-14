This project uses Arduino IDE to code and flash 2 ESP32-S3 dev boards for the project.

To run this project yourself, you will need 2 ESP32 devices that have Bluetooth capabilities (The ESP32-S3 was just the model we used).
Also to flash the code onto the devices, the Arduino IDE will also be needed as well as the libraries and boards used need to be added to Arduino IDE.

Depending on the ESP32 boards used you will have to change the board type when trying to connect to it. The libraries used should be detected and prompted for install when you first
try to upload the code. 

Upload the project_server code onto one board first and make sure your serial monitor is set to a baud rate of 115200.

Upload the project_client code onto the other board and make sure your serial monitor is set to a baud rate of 115200.

Once the boards are flashed they should automatically try to connect. You should see "Shared AES key drived. Handshake complete." on the server serial monitor and
"Ready to chat!" on the client when they are ready to message to each other.

If one device should loose power, both devices will need to be restarted to redo the handshake in the current state.

Each device will print the message it will send and then the cipher text it sent. This is just to monitor in these early stages of development to verify messages
are being encrypted. Only the cipher text is sent.
