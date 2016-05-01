# XComm
The XComm library is a rewrite of BlackBoxSocket from the ground up. Most of the infrastructure is the same. I have just made it easier to use it as a thread, changed the Hmac Parameters and utilized Gson Library in order to send objects.

#How to use it
`XCommThread xct = new XCommThread(Socket, ConcurrentLinkedQueue<String> inQueue, ConcurrentLinkedQueue<String> outQueue, isClient, isClientControlled, localPrivateKey, localPublicKey);`

- Socket: is the socket over which you wish to communicate.
- inQueue: is a concurrentLinkedQueue in which the thread puts all the incomming messages.
- outQueue: is a concurrentLinkedQueue in which the thread reads all outgoing messages and send them on.
- isClient: is a boolean variable to tell the thread that it is to initialize as a client. True means client, false means server.
- isClientControlled: is a boolean variable to tell the thread that it is to generate all the Aes keys and moving factor variables. Setting it to true means that the client generates the keys, else if false, the server will generate the keys and moving factor. This way you could take the burden of generating keys off smaller devices.
- localPrivateKey: the private Key of your device. if this is set to null, XCommThread will automatically generate a random Keypair for you.
- localPublicKey: the public Key of your device. if this is set to null, XCommThread will automatically generate a random Keypair for you.
