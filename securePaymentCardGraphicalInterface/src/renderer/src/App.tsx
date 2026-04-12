import { Dispatch, SetStateAction, useState } from 'react'

import Header from '@renderer/components/Header'
import Divider from '@renderer/components/Divider'
import Authentication from '@renderer/components/Authentication'
import ClientInterface from '@renderer/components/ClientInterface'
import SessionInterface from '@renderer/components/SessionInterface'
import LandingPage from '@renderer/components/LandingPage'

export const SEPARATOR_CHAR: string = "|";
export const AUTHENTICATION_REQUEST: number = 0;
export const DEPLOY: number = 1;
export const START_OR_RESUME_SESSION: number = 2;
export const UNINSTALL: number = 3;
export const CLOSE_CLIENT_INTERFACE: number = 4;

export type Nullable<T> = T | null;
export type setState<T> = Dispatch<SetStateAction<T>>;

function initWebSocketListeners(
  webSocket: WebSocket,
  setLogs: setState<string[]>,
  setConnected: setState<boolean>,
  setAuthenticated: setState<boolean>,
  setSessionStarted: setState<boolean>,
): void {
  webSocket.addEventListener('open', () => {
    setLogs((prevState) => [...prevState, 'La connexion avec le client a été établie avec succès.'])
    setConnected(true)
  })

  webSocket.addEventListener('close', () => {
    setLogs((prevState) => [...prevState, 'Fin de la connexion.'])
    setConnected(false)
  })

  webSocket.addEventListener('message', (e) => {
    const message: string = e.data
    if (message === "L'authentification auprès du serveur a réussi.") {
      setAuthenticated(true)
    }

    if (message === 'La session a démarré') {
      setSessionStarted(true);
    }

    setLogs((prevState) => [...prevState, e.data])
  })

  webSocket.addEventListener('error', () => {
    setLogs((prevState) => [...prevState, `ERROR:`])
  })
}

function connectWebSocket(
  setWebSocketObject: setState<Nullable<WebSocket>>,
  setLogs: setState<string[]>,
  setConnected: setState<boolean>,
  setAuthenticated: setState<boolean>,
  setSessionStarted: setState<boolean>
): WebSocket {
  // Reset
  setLogs([])
  setConnected(false)
  setAuthenticated(false);
  setSessionStarted(false);
  setWebSocketObject(null);

  const url = 'ws://127.0.0.1/'
  const webSocket: WebSocket = new WebSocket(url)
  initWebSocketListeners(webSocket, setLogs, setConnected, setAuthenticated, setSessionStarted)

  setWebSocketObject(webSocket)
  return webSocket
}

function closeWebSocket(
  webSocket: Nullable<WebSocket>,
  setConnected: setState<boolean>,
  setAuthenticated: setState<boolean>,
  setSessionStarted: setState<boolean>,
setWebSocketObject: setState<Nullable<WebSocket>>
): void {
  if (webSocket !== null) {
    webSocket.close()
  }

  setConnected(false)
  setAuthenticated(false)
  setSessionStarted(false);
  setWebSocketObject(null);
}

function App(): React.JSX.Element {
  const [email, setEmail] = useState<string>('')
  const [password, setPassword] = useState<string>('')

  const [logs, setLogs] = useState<string[]>([])
  const [connected, setConnected] = useState<boolean>(false)
  const [authenticated, setAuthenticated] = useState<boolean>(false)
  const [sessionStarted, setSessionStarted] = useState<boolean>(false)
  const [webSocketObject, setWebSocketObject] = useState<Nullable<WebSocket>>(null)

  return (
    <main>
      <Header
        connectWebSocketFunction={() => {
          connectWebSocket(
            setWebSocketObject,
            setLogs,
            setConnected,
            setAuthenticated,
            setSessionStarted
          )
        }}
        closeWebSocketFunction={() => {
          closeWebSocket(
            webSocketObject,
            setConnected,
            setAuthenticated,
            setSessionStarted,
            setWebSocketObject
          )
        }}
        logs={logs}
        connected={connected}
      />


      <Divider />
      {!connected ? <LandingPage /> : <></>}

      {webSocketObject !== null && connected && !authenticated ? (
        <Authentication
          email={email}
          password={password}
          webSocket={webSocketObject}
          setLogs={setLogs}
          setEmail={setEmail}
          setPassword={setPassword}
        />
      ) : (
        <></>
      )}

      {webSocketObject !== null && connected && authenticated ? (
        <ClientInterface webSocket={webSocketObject} sessionStarted={sessionStarted} />
      ) : (
        <></>
      )}

      {webSocketObject !== null && connected && authenticated && sessionStarted ? (
        <SessionInterface />
      ) : (
        <></>
      )}
    </main>
  )
}

export default App
