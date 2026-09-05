import { io } from 'socket.io-client'

// Same-origin Socket.IO connection. In dev the Vite proxy forwards
// /socket.io (with websocket upgrade) to the Flask backend; in
// production Flask serves the built SPA, so same origin just works.
export const socket = io({ autoConnect: false })
