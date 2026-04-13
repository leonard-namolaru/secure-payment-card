import { Dispatch, SetStateAction, useState } from 'react'

import Header from '@renderer/components/Header'
import Divider from '@renderer/components/Divider'
import LandingPage from '@renderer/components/LandingPage'
import Authentication from '@renderer/components/Authentication'
import ClientInterface from '@renderer/components/ClientInterface'
import SessionInterface from '@renderer/components/SessionInterface'

export const GUI_SEPARATOR_CHAR: string = "|";
export const CLIENT_SEPARATOR_CHAR: string = ':';

export const ID_PREFIX: string = 'ID';
export const BALANCE_PREFIX: string = 'Solde';

export const DEBIT_TRANSACTION_MODE: string = 'DEBIT';
export const CREDIT_TRANSACTION_MODE: string = 'CREDIT';

export const AUTHENTICATION_REQUEST: number = 0;
export const DEPLOY: number = 1;
export const START_OR_RESUME_SESSION: number = 2;
export const UNINSTALL: number = 3;
export const CLOSE_CLIENT_INTERFACE: number = 4;
export const DEBIT: number = 5;
export const CREDIT: number = 6;

export type Nullable<T> = T | null;
export type setState<T> = Dispatch<SetStateAction<T>>;

interface SetAppElementsObject {
  setEmail: setState<string>
  setLogs: setState<string[]>
  setBalance: setState<number>
  setPassword: setState<string>
  setConnected: setState<boolean>
  setAuthenticated: setState<boolean>
  setSessionStarted: setState<boolean>
  setTransactionMode: setState<string>
  setSecurePaymentCardID: setState<string>
  setTransactionAmountAsStr: setState<string>
  setWebSocketObject: setState<Nullable<WebSocket>>
}

function initWebSocketListeners(
  webSocket: WebSocket,
  setAppElementsObject: SetAppElementsObject
): void {
  webSocket.addEventListener('open', () => {
    setAppElementsObject.setLogs((prevState) => [
      ...prevState,
      'La connexion avec le client a été établie avec succès.'
    ])
    setAppElementsObject.setConnected(true)
  })

  webSocket.addEventListener('close', () => {
    setAppElementsObject.setLogs((prevState) => [...prevState, 'Fin de la connexion.'])
    setAppElementsObject.setConnected(false)
  })

  webSocket.addEventListener('message', (e) => {
    const message: string = e.data
    if (message.trim() === "L'authentification auprès du serveur a réussi.") {
      setAppElementsObject.setAuthenticated(true)
    }

    if (message.trim() === 'La session a démarré') {
      setAppElementsObject.setSessionStarted(true)
    }

    if (message.trim().startsWith(ID_PREFIX) && message.indexOf(CLIENT_SEPARATOR_CHAR) !== -1) {
      let securePaymentCardID: string = ''
      const tmp: string[] = message.split(CLIENT_SEPARATOR_CHAR).map((str) => str.trim())
      if (tmp.length > 1) {
        securePaymentCardID = tmp[1]
      }

      setAppElementsObject.setSecurePaymentCardID(securePaymentCardID)
      return
    }

    if (message.trim().startsWith(BALANCE_PREFIX) && message.indexOf(CLIENT_SEPARATOR_CHAR) !== -1) {
      let balance: number = -1
      const tmp: string[] = message.split(CLIENT_SEPARATOR_CHAR).map((str) => str.trim())
      if (tmp.length > 1) {
        balance = parseInt(tmp[1])
      }

      if (!isNaN(balance)) {
        setAppElementsObject.setBalance(balance)
      }
      return
    }

    setAppElementsObject.setLogs((prevState) => [...prevState, e.data])
  })

  webSocket.addEventListener('error', () => {
    setAppElementsObject.setLogs((prevState) => [...prevState, `ERROR:`])
  })
}


function connectWebSocket(setAppElementsObject: SetAppElementsObject): WebSocket {
  // Reset
  setAppElementsObject.setLogs([])
  setAppElementsObject.setConnected(false)
  setAppElementsObject.setAuthenticated(false)
  setAppElementsObject.setSessionStarted(false)
  setAppElementsObject.setWebSocketObject(null)

  const url = 'ws://127.0.0.1/'
  const webSocket: WebSocket = new WebSocket(url)
  initWebSocketListeners(webSocket, setAppElementsObject)
  setAppElementsObject.setWebSocketObject(webSocket)
  return webSocket
}

function closeWebSocket(
  webSocket: Nullable<WebSocket>,
  setAppElementsObject: SetAppElementsObject
): void {
  if (webSocket !== null) {
    webSocket.close()
  }

  setAppElementsObject.setConnected(false)
  setAppElementsObject.setAuthenticated(false)
  setAppElementsObject.setSessionStarted(false)
  setAppElementsObject.setWebSocketObject(null)
}

function App(): React.JSX.Element {
  const [email, setEmail] = useState<string>('')
  const [password, setPassword] = useState<string>('')

  const [balance, setBalance] = useState<number>(-1)
  const [securePaymentCardID, setSecurePaymentCardID] = useState<string>('')

  const [logs, setLogs] = useState<string[]>([])
  const [connected, setConnected] = useState<boolean>(false)
  const [authenticated, setAuthenticated] = useState<boolean>(false)
  const [sessionStarted, setSessionStarted] = useState<boolean>(false)
  const [webSocketObject, setWebSocketObject] = useState<Nullable<WebSocket>>(null)

  const [transactionMode, setTransactionMode] = useState<string>('')
  const [transactionAmountAsStr, setTransactionAmountAsStr] = useState<string>('')

  const setAppElementsObject: SetAppElementsObject = {
    setLogs: setLogs,
    setEmail: setEmail,
    setBalance: setBalance,
    setPassword: setPassword,
    setConnected: setConnected,
    setAuthenticated: setAuthenticated,
    setSessionStarted: setSessionStarted,
    setTransactionMode: setTransactionMode,
    setWebSocketObject: setWebSocketObject,
    setSecurePaymentCardID: setSecurePaymentCardID,
    setTransactionAmountAsStr: setTransactionAmountAsStr
  }


  return (
    <main>
      <Header
        connectWebSocketFunction={() => {
          connectWebSocket(setAppElementsObject)
        }}
        closeWebSocketFunction={() => {
          closeWebSocket(webSocketObject, setAppElementsObject)
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
        <ClientInterface
          webSocket={webSocketObject}
          sessionStarted={sessionStarted}
          securePaymentCardID={securePaymentCardID}
          balance={balance}
        />
      ) : (
        <></>
      )}

      {webSocketObject !== null && connected && authenticated && sessionStarted ? (
        <SessionInterface
          setLogs={setLogs}
          webSocket={webSocketObject}
          transactionMode={transactionMode}
          setTransactionMode={setTransactionMode}
          transactionAmountAsStr={transactionAmountAsStr}
          setTransactionAmountAsStr={setTransactionAmountAsStr}
        />
      ) : (
        <></>
      )}
    </main>
  )
}

export default App
